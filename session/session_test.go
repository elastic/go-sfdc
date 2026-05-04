package session

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-sfdc"
	"github.com/elastic/go-sfdc/credentials"
	"github.com/elastic/go-sfdc/internal/testkeys"
)

type trackingReadCloser struct {
	reader io.Reader
	closed bool
}

func (body *trackingReadCloser) Read(p []byte) (int, error) {
	return body.reader.Read(p)
}

func (body *trackingReadCloser) Close() error {
	body.closed = true
	return nil
}

type errReader struct {
	err error
}

func (reader errReader) Read([]byte) (int, error) {
	return 0, reader.err
}

func TestNewOAuthTokenRequest(t *testing.T) {
	scenarios := []struct {
		desc  string
		creds credentials.PasswordCredentials
		err   error
	}{
		{
			desc: "Passing HTTP request",
			creds: credentials.PasswordCredentials{
				URL:          "http://test.password.session",
				Username:     "myusername",
				Password:     "12345",
				ClientID:     "some client id",
				ClientSecret: "shhhh its a secret",
			},
			err: nil,
		},
		{
			desc: "Bad URL",
			creds: credentials.PasswordCredentials{
				URL:          "123://something.com",
				Username:     "myusername",
				Password:     "12345",
				ClientID:     "some client id",
				ClientSecret: "shhhh its a secret",
			},
			err: errors.New("parse \"123://something.com/services/oauth2/token\": first path segment in URL cannot contain colon"),
		},
	}

	for _, scenario := range scenarios {

		passwordCreds, err := credentials.NewPasswordCredentials(scenario.creds)
		if err != nil {
			t.Fatal("password credentials can not return an error for these tests")
		}
		request, err := newOAuthTokenRequest(passwordCreds)

		if err != nil && scenario.err == nil {
			t.Errorf("%s Error was not expected %s", scenario.desc, err.Error())
		} else if err == nil && scenario.err != nil {
			t.Errorf("%s Error was expected %s", scenario.desc, scenario.err.Error())
		} else {
			if err != nil {
				if err.Error() != scenario.err.Error() {
					t.Errorf("%s Error %s :: %s", scenario.desc, err.Error(), scenario.err.Error())
				}
			} else {
				if request.Method != http.MethodPost {
					t.Errorf("%s HTTP request method needs to be POST not %s", scenario.desc, request.Method)
				}

				if request.URL.String() != scenario.creds.URL+oauthEndpoint {
					t.Errorf("%s URL not matching %s :: %s", scenario.desc, scenario.creds.URL+oauthEndpoint, request.URL.String())
				}

				buf, err := ioutil.ReadAll(request.Body)
				request.Body.Close()
				if err != nil {
					t.Fatal(err.Error())
				}
				reader, err := passwordCreds.Retrieve()
				if err != nil {
					t.Fatal(err.Error())
				}
				body, err := ioutil.ReadAll(reader)
				if err != nil {
					t.Fatal(err.Error())
				}

				if string(body) != string(buf) {
					t.Errorf("%s Form data %s :: %s", scenario.desc, string(buf), string(body))
				}
			}
		}
	}
}

func TestExchangeOAuthToken(t *testing.T) {
	scenarios := []struct {
		desc     string
		url      string
		client   *http.Client
		response *oauthTokenResponse
		err      error
	}{
		{
			desc: "Passing Response",
			url:  "http://example.com/foo",
			client: mockHTTPClient(func(req *http.Request) *http.Response {
				resp := `
				{
					"access_token": "token",
					"instance_url": "https://some.salesforce.instance.com",
					"id": "https://test.salesforce.com/id/123456789",
					"token_type": "Bearer",
					"issued_at": "1553568410028",
					"signature": "hello"
				}`

				return &http.Response{
					StatusCode: 200,
					Body:       ioutil.NopCloser(strings.NewReader(resp)),
					Header:     make(http.Header),
				}
			}),
			response: &oauthTokenResponse{
				AccessToken: "token",
				InstanceURL: "https://some.salesforce.instance.com",
				ID:          "https://test.salesforce.com/id/123456789",
				TokenType:   "Bearer",
				IssuedAt:    "1553568410028",
				Signature:   "hello",
			},
			err: nil,
		},
		{
			desc: "Failed Response",
			url:  "http://example.com/foo",
			client: mockHTTPClient(func(req *http.Request) *http.Response {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Status:     "Some status",
					Body:       ioutil.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}
			}),
			response: &oauthTokenResponse{},
			err:      fmt.Errorf("session response error: %d %s", http.StatusInternalServerError, "Some status"),
		},
		{
			desc: "Response Decode Error",
			url:  "http://example.com/foo",
			client: mockHTTPClient(func(req *http.Request) *http.Response {
				resp := `
				{
					"access_token": "token",
					"instance_url": "https://some.salesforce.instance.com",
					"id": "https://test.salesforce.com/id/123456789",
					"token_type": "Bearer",
					"issued_at": "1553568410028",
					"signature": "hello",
				}`

				return &http.Response{
					StatusCode: 200,
					Body:       ioutil.NopCloser(strings.NewReader(resp)),
					Header:     make(http.Header),
				}
			}),
			response: &oauthTokenResponse{},
			err:      errors.New("invalid character '}' looking for beginning of object key string"),
		},
	}

	for _, scenario := range scenarios {

		request, err := http.NewRequest(http.MethodPost, scenario.url, nil)
		if err != nil {
			t.Fatal(err.Error())
		}

		response, err := exchangeOAuthToken(request, scenario.client)

		if err != nil && scenario.err == nil {
			t.Errorf("%s Error was not expected %s", scenario.desc, err.Error())
		} else if err == nil && scenario.err != nil {
			t.Errorf("%s Error was expected %s", scenario.desc, scenario.err.Error())
		} else {
			if err != nil {
				if err.Error() != scenario.err.Error() {
					t.Errorf("%s Error %s :: %s", scenario.desc, err.Error(), scenario.err.Error())
				}
			} else {
				if response.AccessToken != scenario.response.AccessToken {
					t.Errorf("%s Access Tokens %s %s", scenario.desc, scenario.response.AccessToken, response.AccessToken)
				}

				if response.InstanceURL != scenario.response.InstanceURL {
					t.Errorf("%s Instance URL %s %s", scenario.desc, scenario.response.InstanceURL, response.InstanceURL)
				}

				if response.ID != scenario.response.ID {
					t.Errorf("%s ID %s %s", scenario.desc, scenario.response.ID, response.ID)
				}

				if response.TokenType != scenario.response.TokenType {
					t.Errorf("%s Token Type %s %s", scenario.desc, scenario.response.TokenType, response.TokenType)
				}

				if response.IssuedAt != scenario.response.IssuedAt {
					t.Errorf("%s Issued At %s %s", scenario.desc, scenario.response.IssuedAt, response.IssuedAt)
				}

				if response.Signature != scenario.response.Signature {
					t.Errorf("%s Signature %s %s", scenario.desc, scenario.response.Signature, response.Signature)
				}

			}
		}

	}
}

func TestExchangeOAuthToken_ClosesResponseBodyOnStatusError(t *testing.T) {
	body := &trackingReadCloser{reader: strings.NewReader(`{"error":"boom"}`)}
	client := mockHTTPClient(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Status:     "500 Internal Server Error",
			Body:       body,
			Header:     make(http.Header),
		}
	})

	request, err := http.NewRequest(http.MethodPost, "http://example.com/foo", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v, want nil", err)
	}

	_, err = exchangeOAuthToken(request, client)
	if err == nil {
		t.Fatal("exchangeOAuthToken() error = nil, want non-nil")
	}
	if !body.closed {
		t.Fatal("exchangeOAuthToken() did not close response body on status error")
	}
}

func TestAuthRefreshTransport_RoundTripReturnsNilResponseOnInspectionError(t *testing.T) {
	readErr := errors.New("read failure")
	body := &trackingReadCloser{reader: errReader{err: readErr}}
	transport := &authRefreshTransport{
		session: &Session{},
		base: roundTripFunc(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Status:     "401 Unauthorized",
				Body:       body,
				Header:     make(http.Header),
			}
		}),
	}

	request, err := http.NewRequest(http.MethodGet, "https://instance.salesforce.example.com/resource", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v, want nil", err)
	}
	request.Header.Set("Authorization", "Bearer expired")

	response, err := transport.RoundTrip(request)
	if err == nil {
		t.Fatal("RoundTrip() error = nil, want non-nil")
	}
	if !errors.Is(err, readErr) {
		t.Fatalf("RoundTrip() error = %v, want %v", err, readErr)
	}
	if response != nil {
		t.Fatalf("RoundTrip() response = %#v, want nil", response)
	}
	if !body.closed {
		t.Fatal("RoundTrip() did not close response body on inspection error")
	}
}

func TestSessionRefresh_DoesNotBlockAuthorizationHeader(t *testing.T) {
	passwordCreds, err := credentials.NewPasswordCredentials(credentials.PasswordCredentials{
		URL:          "https://login.salesforce.example.com",
		Username:     "myusername",
		Password:     "12345",
		ClientID:     "some client id",
		ClientSecret: "shhhh its a secret",
	})
	if err != nil {
		t.Fatalf("credentials.NewPasswordCredentials() error = %v, want nil", err)
	}

	authStarted := make(chan struct{})
	releaseAuth := make(chan struct{})
	refreshDone := make(chan error, 1)
	client := mockHTTPClient(func(req *http.Request) *http.Response {
		if req.URL.Path != oauthEndpoint {
			t.Fatalf("unexpected request path %q", req.URL.Path)
		}
		close(authStarted)
		<-releaseAuth
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: ioutil.NopCloser(strings.NewReader(`{
				"access_token": "refreshed",
				"instance_url": "https://instance.salesforce.example.com",
				"id": "https://test.salesforce.com/id/123456789",
				"token_type": "Bearer",
				"issued_at": "1553568410028",
				"signature": "hello"
			}`)),
			Header: make(http.Header),
		}
	})

	session := &Session{
		response: &oauthTokenResponse{
			AccessToken: "expired",
			InstanceURL: "https://instance.salesforce.example.com",
			ID:          "https://test.salesforce.com/id/123456789",
			TokenType:   "Bearer",
			IssuedAt:    "1553568410028",
			Signature:   "hello",
		},
		config: sfdc.Configuration{
			Credentials: passwordCreds,
			Client:      client,
			Version:     45,
		},
	}

	go func() {
		refreshDone <- session.refresh("Bearer expired")
	}()

	<-authStarted

	request, err := http.NewRequest(http.MethodGet, "https://instance.salesforce.example.com/resource", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v, want nil", err)
	}

	authHeaderDone := make(chan struct{})
	go func() {
		session.AuthorizationHeader(request)
		close(authHeaderDone)
	}()

	select {
	case <-authHeaderDone:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("AuthorizationHeader blocked while refresh was in flight")
	}

	if got, want := request.Header.Get("Authorization"), "Bearer expired"; got != want {
		t.Fatalf("AuthorizationHeader() = %q, want %q while refresh is in flight", got, want)
	}

	close(releaseAuth)

	if err := <-refreshDone; err != nil {
		t.Fatalf("refresh() error = %v, want nil", err)
	}

	nextRequest, err := http.NewRequest(http.MethodGet, "https://instance.salesforce.example.com/resource", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v, want nil", err)
	}
	session.AuthorizationHeader(nextRequest)
	if got, want := nextRequest.Header.Get("Authorization"), "Bearer refreshed"; got != want {
		t.Fatalf("AuthorizationHeader() = %q, want %q after refresh completes", got, want)
	}
}

func testNewPasswordCredentials(cred credentials.PasswordCredentials) *credentials.Credentials {
	creds, err := credentials.NewPasswordCredentials(cred)
	if err != nil {
		return nil
	}
	return creds
}

func TestOpen(t *testing.T) {
	scenarios := []struct {
		desc    string
		config  sfdc.Configuration
		session *Session
		err     error
	}{
		{
			desc: "Passing",
			config: sfdc.Configuration{
				Credentials: testNewPasswordCredentials(credentials.PasswordCredentials{
					URL:          "http://test.password.session",
					Username:     "myusername",
					Password:     "12345",
					ClientID:     "some client id",
					ClientSecret: "shhhh its a secret",
				}),
				Client: mockHTTPClient(func(req *http.Request) *http.Response {
					resp := `
					{
						"access_token": "token",
						"instance_url": "https://some.salesforce.instance.com",
						"id": "https://test.salesforce.com/id/123456789",
						"token_type": "Bearer",
						"issued_at": "1553568410028",
						"signature": "hello"
					}`

					return &http.Response{
						StatusCode: 200,
						Body:       ioutil.NopCloser(strings.NewReader(resp)),
						Header:     make(http.Header),
					}
				}),
				Version: 45,
			},
			session: &Session{
				response: &oauthTokenResponse{
					AccessToken: "token",
					InstanceURL: "https://some.salesforce.instance.com",
					ID:          "https://test.salesforce.com/id/123456789",
					TokenType:   "Bearer",
					IssuedAt:    "1553568410028",
					Signature:   "hello",
				},
			},
			err: nil,
		},

		{
			desc: "Error Request",
			config: sfdc.Configuration{
				Credentials: testNewPasswordCredentials(credentials.PasswordCredentials{
					URL:          "123://test.password.session",
					Username:     "myusername",
					Password:     "12345",
					ClientID:     "some client id",
					ClientSecret: "shhhh its a secret",
				}),
				Client: mockHTTPClient(func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode: 500,
						Header:     make(http.Header),
					}
				}),
				Version: 45,
			},
			session: nil,
			err:     errors.New("parse \"123://test.password.session/services/oauth2/token\": first path segment in URL cannot contain colon"),
		},
		{
			desc: "Error Response",
			config: sfdc.Configuration{
				Credentials: testNewPasswordCredentials(credentials.PasswordCredentials{
					URL:          "http://test.password.session",
					Username:     "myusername",
					Password:     "12345",
					ClientID:     "some client id",
					ClientSecret: "shhhh its a secret",
				}),
				Client: mockHTTPClient(func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode: http.StatusInternalServerError,
						Status:     "Some status",
						Body:       ioutil.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}
				}),
				Version: 45,
			},
			session: nil,
			err:     fmt.Errorf("session response error: %d %s", http.StatusInternalServerError, "Some status"),
		},
	}

	for _, scenario := range scenarios {

		session, err := Open(scenario.config)

		if err != nil && scenario.err == nil {
			t.Errorf("%s Error was not expected %s", scenario.desc, err.Error())
		} else if err == nil && scenario.err != nil {
			t.Errorf("%s Error was expected %s", scenario.desc, scenario.err.Error())
		} else {
			if err != nil {
				if err.Error() != scenario.err.Error() {
					t.Errorf("%s Error %s :: %s", scenario.desc, err.Error(), scenario.err.Error())
				}
			} else {
				if session.response.AccessToken != scenario.session.response.AccessToken {
					t.Errorf("%s Access Tokens %s %s", scenario.desc, scenario.session.response.AccessToken, session.response.AccessToken)
				}

				if session.response.InstanceURL != scenario.session.response.InstanceURL {
					t.Errorf("%s Instance URL %s %s", scenario.desc, scenario.session.response.InstanceURL, session.response.InstanceURL)
				}

				if session.response.ID != scenario.session.response.ID {
					t.Errorf("%s ID %s %s", scenario.desc, scenario.session.response.ID, session.response.ID)
				}

				if session.response.TokenType != scenario.session.response.TokenType {
					t.Errorf("%s Token Type %s %s", scenario.desc, scenario.session.response.TokenType, session.response.TokenType)
				}

				if session.response.IssuedAt != scenario.session.response.IssuedAt {
					t.Errorf("%s Issued At %s %s", scenario.desc, scenario.session.response.IssuedAt, session.response.IssuedAt)
				}

				if session.response.Signature != scenario.session.response.Signature {
					t.Errorf("%s Signature %s %s", scenario.desc, scenario.session.response.Signature, session.response.Signature)
				}

			}
		}

	}
}

func TestSession_ServiceURL(t *testing.T) {
	type fields struct {
		response *oauthTokenResponse
		config   sfdc.Configuration
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Passing URL",
			fields: fields{
				response: &oauthTokenResponse{
					InstanceURL: "https://www.my.salesforce.instance",
				},
				config: sfdc.Configuration{
					Version: 43,
				},
			},
			want: "https://www.my.salesforce.instance/services/data/v43.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				response: tt.fields.response,
				config:   tt.fields.config,
			}
			if got := session.ServiceURL(); got != tt.want {
				t.Errorf("Session.ServiceURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_AuthorizationHeader(t *testing.T) {
	type fields struct {
		response *oauthTokenResponse
		config   sfdc.Configuration
	}
	type args struct {
		request *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "Authorization Test",
			fields: fields{
				response: &oauthTokenResponse{
					TokenType:   "Type",
					AccessToken: "Access",
				},
				config: sfdc.Configuration{},
			},
			args: args{
				request: &http.Request{
					Header: make(http.Header),
				},
			},
			want: "Type Access",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				response: tt.fields.response,
				config:   tt.fields.config,
			}
			session.AuthorizationHeader(tt.args.request)

			if got := tt.args.request.Header.Get("Authorization"); got != tt.want {
				t.Errorf("Session.AuthorizationHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_Client(t *testing.T) {
	type fields struct {
		response *oauthTokenResponse
		config   sfdc.Configuration
	}
	tests := []struct {
		name   string
		fields fields
		want   *http.Client
	}{
		{
			name: "Session Client",
			fields: fields{
				response: &oauthTokenResponse{},
				config: sfdc.Configuration{
					Client: http.DefaultClient,
				},
			},
			want: http.DefaultClient,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				response: tt.fields.response,
				config:   tt.fields.config,
			}
			if got := session.Client(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Session.Client() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_InstanceURL(t *testing.T) {
	type fields struct {
		response *oauthTokenResponse
		config   sfdc.Configuration
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Passing URL",
			fields: fields{
				response: &oauthTokenResponse{
					InstanceURL: "https://www.my.salesforce.instance",
				},
				config: sfdc.Configuration{
					Version: 43,
				},
			},
			want: "https://www.my.salesforce.instance",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				response: tt.fields.response,
				config:   tt.fields.config,
			}
			if got := session.InstanceURL(); got != tt.want {
				t.Errorf("Session.InstanceURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_ClientReauthenticatesAfterInvalidAuthErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		status     string
		errorCode  string
	}{
		{
			name:       "invalid auth header",
			statusCode: http.StatusBadRequest,
			status:     "400 Bad Request",
			errorCode:  "INVALID_AUTH_HEADER",
		},
		{
			name:       "invalid session id",
			statusCode: http.StatusUnauthorized,
			status:     "401 Unauthorized",
			errorCode:  "INVALID_SESSION_ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			passwordCreds, err := credentials.NewPasswordCredentials(credentials.PasswordCredentials{
				URL:          "https://login.salesforce.example.com",
				Username:     "myusername",
				Password:     "12345",
				ClientID:     "some client id",
				ClientSecret: "shhhh its a secret",
			})
			if err != nil {
				t.Fatalf("credentials.NewPasswordCredentials() error = %v, want nil", err)
			}

			authCalls := 0
			resourceCalls := 0
			var authHeaders []string

			client := mockHTTPClient(func(req *http.Request) *http.Response {
				switch req.URL.Path {
				case oauthEndpoint:
					authCalls++
					token := "expired"
					if authCalls > 1 {
						token = "refreshed"
					}

					return &http.Response{
						StatusCode: http.StatusOK,
						Body: ioutil.NopCloser(strings.NewReader(fmt.Sprintf(`{
							"access_token": %q,
							"instance_url": "https://instance.salesforce.example.com",
							"id": "https://test.salesforce.com/id/123456789",
							"token_type": "Bearer",
							"issued_at": "1553568410028",
							"signature": "hello"
						}`, token))),
						Header: make(http.Header),
					}
				case "/resource":
					resourceCalls++
					authHeaders = append(authHeaders, req.Header.Get("Authorization"))
					if resourceCalls == 1 {
						return &http.Response{
							StatusCode: tt.statusCode,
							Status:     tt.status,
							Body: ioutil.NopCloser(strings.NewReader(fmt.Sprintf(`[{
								"message": "Session expired or invalid",
								"errorCode": %q
							}]`, tt.errorCode))),
							Header: make(http.Header),
						}
					}

					return &http.Response{
						StatusCode: http.StatusOK,
						Status:     "200 OK",
						Body:       ioutil.NopCloser(strings.NewReader(`{}`)),
						Header:     make(http.Header),
					}
				default:
					t.Fatalf("unexpected request path %q", req.URL.Path)
					return nil
				}
			})

			session, err := Open(sfdc.Configuration{
				Credentials: passwordCreds,
				Client:      client,
				Version:     45,
			})
			if err != nil {
				t.Fatalf("Open() error = %v, want nil", err)
			}

			request, err := http.NewRequest(http.MethodGet, "https://instance.salesforce.example.com/resource", nil)
			if err != nil {
				t.Fatalf("http.NewRequest() error = %v, want nil", err)
			}
			session.AuthorizationHeader(request)

			response, err := session.Client().Do(request)
			if err != nil {
				t.Fatalf("Session.Client().Do() error = %v, want nil", err)
			}
			defer response.Body.Close()

			if response.StatusCode != http.StatusOK {
				t.Fatalf("Session.Client().Do() status = %d, want %d", response.StatusCode, http.StatusOK)
			}
			if authCalls != 2 {
				t.Fatalf("auth calls = %d, want 2", authCalls)
			}
			if resourceCalls != 2 {
				t.Fatalf("resource calls = %d, want 2", resourceCalls)
			}
			if !reflect.DeepEqual(authHeaders, []string{"Bearer expired", "Bearer refreshed"}) {
				t.Fatalf("authorization headers = %v, want %v", authHeaders, []string{"Bearer expired", "Bearer refreshed"})
			}

			nextRequest, err := http.NewRequest(http.MethodGet, "https://instance.salesforce.example.com/resource", nil)
			if err != nil {
				t.Fatalf("http.NewRequest() error = %v, want nil", err)
			}
			session.AuthorizationHeader(nextRequest)
			if got, want := nextRequest.Header.Get("Authorization"), "Bearer refreshed"; got != want {
				t.Fatalf("Session.AuthorizationHeader() = %q, want %q", got, want)
			}
		})
	}
}

func TestSession_ClientReauthenticatesWithJWTCredentials(t *testing.T) {
	jwtCreds, err := credentials.NewJWTCredentials(credentials.JwtCredentials{
		URL:            "https://login.salesforce.example.com",
		ClientId:       "some client id",
		ClientUsername: "myusername",
		ClientKey:      testkeys.MustParseRSAPrivateKey(t),
	})
	if err != nil {
		t.Fatalf("credentials.NewJWTCredentials() error = %v, want nil", err)
	}

	authCalls := 0
	resourceCalls := 0
	var authGrantTypes []string
	var authHeaders []string

	client := mockHTTPClient(func(req *http.Request) *http.Response {
		switch req.URL.Path {
		case oauthEndpoint:
			authCalls++
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("ReadAll(token request body) error = %v, want nil", err)
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatalf("ParseQuery(token request body) error = %v, want nil", err)
			}
			authGrantTypes = append(authGrantTypes, values.Get("grant_type"))
			if values.Get("assertion") == "" {
				t.Fatal("JWT token request assertion is empty")
			}

			token := "expired"
			if authCalls > 1 {
				token = "refreshed"
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body: ioutil.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"access_token": %q,
					"instance_url": "https://instance.salesforce.example.com",
					"id": "https://test.salesforce.com/id/123456789",
					"token_type": "Bearer",
					"issued_at": "1553568410028",
					"signature": "hello"
				}`, token))),
				Header: make(http.Header),
			}
		case "/resource":
			resourceCalls++
			authHeaders = append(authHeaders, req.Header.Get("Authorization"))
			if resourceCalls == 1 {
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Status:     "401 Unauthorized",
					Body: ioutil.NopCloser(strings.NewReader(`[{
						"message": "Session expired or invalid",
						"errorCode": "INVALID_SESSION_ID"
					}]`)),
					Header: make(http.Header),
				}
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       ioutil.NopCloser(strings.NewReader(`{}`)),
				Header:     make(http.Header),
			}
		default:
			t.Fatalf("unexpected request path %q", req.URL.Path)
			return nil
		}
	})

	session, err := Open(sfdc.Configuration{
		Credentials: jwtCreds,
		Client:      client,
		Version:     45,
	})
	if err != nil {
		t.Fatalf("Open() error = %v, want nil", err)
	}

	request, err := http.NewRequest(http.MethodGet, "https://instance.salesforce.example.com/resource", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v, want nil", err)
	}
	session.AuthorizationHeader(request)

	response, err := session.Client().Do(request)
	if err != nil {
		t.Fatalf("Session.Client().Do() error = %v, want nil", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("Session.Client().Do() status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if authCalls != 2 {
		t.Fatalf("auth calls = %d, want 2", authCalls)
	}
	if !reflect.DeepEqual(authGrantTypes, []string{"urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant-type:jwt-bearer"}) {
		t.Fatalf("auth grant types = %v, want JWT bearer grant twice", authGrantTypes)
	}
	if resourceCalls != 2 {
		t.Fatalf("resource calls = %d, want 2", resourceCalls)
	}
	if !reflect.DeepEqual(authHeaders, []string{"Bearer expired", "Bearer refreshed"}) {
		t.Fatalf("authorization headers = %v, want %v", authHeaders, []string{"Bearer expired", "Bearer refreshed"})
	}
}
