// Package session handles creation of a Salesforce session.
package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/elastic/go-sfdc"
	"github.com/elastic/go-sfdc/credentials"
)

// Session is the authentication response. This is used to generate the
// authorization header for the Salesforce API calls.
type Session struct {
	response  *oauthTokenResponse
	config    sfdc.Configuration
	client    *http.Client
	mu        sync.RWMutex
	refreshMu sync.Mutex
}

// Clienter interface provides the HTTP client used by the
// the resources.
type Clienter interface {
	Client() *http.Client
}

// InstanceFormatter is the session interface that
// formats the session instance information used
// by the resources.
//
// InstanceURL will return the Salesforce instance.
//
// AuthorizationHeader will add the authorization to the
// HTTP request's header.
type InstanceFormatter interface {
	InstanceURL() string
	AuthorizationHeader(*http.Request)
	Clienter
}

// ServiceFormatter is the session interface that
// formats the session for service resources.
//
// ServiceURL provides the service URL for resources to
// use.
type ServiceFormatter interface {
	InstanceFormatter
	ServiceURL() string
}

// oauthTokenResponse is the JSON body from POST /services/oauth2/token for
// standard OAuth grants (e.g. password, JWT bearer), not password-only.
type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	InstanceURL string `json:"instance_url"`
	ID          string `json:"id"`
	TokenType   string `json:"token_type"`
	IssuedAt    string `json:"issued_at"`
	Signature   string `json:"signature"`
}

const oauthEndpoint = "/services/oauth2/token"

var invalidAuthErrorCodes = map[string]struct{}{
	"INVALID_AUTH_HEADER": {},
	"INVALID_SESSION_ID":  {},
}

// Open is used to authenticate with Salesforce and open a session. The user will need to
// supply the proper credentials and a HTTP client.
//
// The returned session's Client wraps the configured HTTP client. Requests made
// through Session.Client() are retried once after a Salesforce-shaped expired
// authentication response, using the same credential provider to get a new token.
func Open(config sfdc.Configuration) (*Session, error) {
	if config.Credentials == nil {
		return nil, errors.New("session: configuration credentials can not be nil")
	}
	if config.Client == nil {
		return nil, errors.New("session: configuration client can not be nil")
	}
	if config.Version <= 0 {
		return nil, errors.New("session: configuration version can not be less than zero")
	}
	request, err := newOAuthTokenRequest(config.Credentials)
	if err != nil {
		return nil, err
	}

	response, err := exchangeOAuthToken(request, config.Client)
	if err != nil {
		return nil, err
	}

	session := &Session{
		response: response,
		config:   config,
	}
	session.client = newRefreshingClient(config.Client, session)

	return session, nil
}

// newOAuthTokenRequest builds the token POST for any credentials.Provider
// (password grant, JWT bearer, or a custom provider).
func newOAuthTokenRequest(creds *credentials.Credentials) (*http.Request, error) {
	oauthURL := creds.URL() + oauthEndpoint

	body, err := creds.Retrieve()
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, oauthURL, body)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Accept", "application/json")
	return request, nil
}

func exchangeOAuthToken(request *http.Request, client *http.Client) (*oauthTokenResponse, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("session response error: %d %s", response.StatusCode, response.Status)
	}
	decoder := json.NewDecoder(response.Body)

	var token oauthTokenResponse
	err = decoder.Decode(&token)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

// InstanceURL will return the Salesforce instance
// from the session authentication.
func (session *Session) InstanceURL() string {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.response.InstanceURL
}

// ServiceURL will return the Salesforce instance for the
// service URL.
func (session *Session) ServiceURL() string {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return fmt.Sprintf("%s/services/data/v%d.0", session.response.InstanceURL, session.config.Version)
}

// AuthorizationHeader will add the authorization to the
// HTTP request's header.
func (session *Session) AuthorizationHeader(request *http.Request) {
	request.Header.Set("Authorization", session.authorizationValue())
}

// Client returns the HTTP client to be used in API calls. The client retries
// once after Salesforce returns a JSON auth error for an expired session.
func (session *Session) Client() *http.Client {
	if session.client != nil {
		return session.client
	}
	return session.config.Client
}

func (session *Session) authorizationValue() string {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return fmt.Sprintf("%s %s", session.response.TokenType, session.response.AccessToken)
}

func (session *Session) refresh(failedAuthorization string) error {
	session.refreshMu.Lock()
	defer session.refreshMu.Unlock()

	if failedAuthorization != "" && session.authorizationValue() != failedAuthorization {
		return nil
	}

	request, err := newOAuthTokenRequest(session.config.Credentials)
	if err != nil {
		return err
	}

	response, err := exchangeOAuthToken(request, session.config.Client)
	if err != nil {
		return err
	}

	session.mu.Lock()
	session.response = response
	session.mu.Unlock()
	return nil
}

type salesforceErrorResponse struct {
	ErrorCode string `json:"errorCode"`
}

type authRefreshTransport struct {
	session *Session
	base    http.RoundTripper
}

func newRefreshingClient(client *http.Client, session *Session) *http.Client {
	cloned := *client
	cloned.Transport = &authRefreshTransport{
		session: session,
		base:    transportFor(client),
	}
	return &cloned
}

func transportFor(client *http.Client) http.RoundTripper {
	if client.Transport != nil {
		return client.Transport
	}
	return http.DefaultTransport
}

func (transport *authRefreshTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	failedAuthorization := request.Header.Get("Authorization")
	retryRequest, err := cloneRequestForRetry(request)
	if err != nil {
		retryRequest = nil
	}

	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if retryRequest == nil {
		return response, nil
	}

	invalidAuth, err := isInvalidAuthResponse(response)
	if err != nil {
		if response.Body != nil {
			response.Body.Close()
		}
		return nil, err
	}
	if !invalidAuth {
		return response, nil
	}

	if err := transport.session.refresh(failedAuthorization); err != nil {
		return response, nil
	}

	response.Body.Close()
	transport.session.AuthorizationHeader(retryRequest)
	return transport.base.RoundTrip(retryRequest)
}

func isInvalidAuthResponse(response *http.Response) (bool, error) {
	if response == nil {
		return false, nil
	}
	if response.StatusCode != http.StatusBadRequest && response.StatusCode != http.StatusUnauthorized {
		return false, nil
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		response.Body.Close()
		return false, err
	}
	response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))

	var errorResponses []salesforceErrorResponse
	if err := json.Unmarshal(body, &errorResponses); err != nil {
		var errorResponse salesforceErrorResponse
		if err := json.Unmarshal(body, &errorResponse); err != nil {
			return false, nil
		}
		errorResponses = []salesforceErrorResponse{errorResponse}
	}

	for _, errorResponse := range errorResponses {
		if _, ok := invalidAuthErrorCodes[errorResponse.ErrorCode]; ok {
			return true, nil
		}
	}

	return false, nil
}

func cloneRequestForRetry(request *http.Request) (*http.Request, error) {
	cloned := request.Clone(request.Context())
	if request.Body == nil {
		return cloned, nil
	}
	if request.GetBody == nil {
		return nil, errors.New("session: request body can not be replayed")
	}

	body, err := request.GetBody()
	if err != nil {
		return nil, err
	}
	cloned.Body = body
	return cloned, nil
}
