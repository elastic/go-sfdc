package soql

import (
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/elastic/go-sfdc"
	"github.com/elastic/go-sfdc/credentials"
	"github.com/elastic/go-sfdc/session"
)

func testNewQueryRecords(records []map[string]interface{}) []*QueryRecord {
	recs := make([]*QueryRecord, len(records))
	for idx, record := range records {
		rec, err := newQueryRecord(record, nil)
		if err != nil {
			return nil
		}
		recs[idx] = rec
	}
	return recs
}
func Test_newQueryResult(t *testing.T) {
	type args struct {
		response queryResponse
	}
	tests := []struct {
		name    string
		args    args
		want    *QueryResult
		wantErr bool
	}{
		{
			name: "No sub results",
			args: args{
				response: queryResponse{
					Done:      true,
					TotalSize: 2,
					Records: []map[string]interface{}{
						{
							"attributes": map[string]interface{}{
								"type": "Account",
								"url":  "/services/data/v20.0/sobjects/Account/001D000000IRFmaIAH",
							},
							"Name": "Test 1",
						},
						{
							"attributes": map[string]interface{}{
								"type": "Account",
								"url":  "/services/data/v20.0/sobjects/Account/001D000000IomazIAB",
							},
							"Name": "Test 2",
						},
					},
				},
			},
			want: &QueryResult{
				response: queryResponse{
					Done:      true,
					TotalSize: 2,
					Records: []map[string]interface{}{
						{
							"attributes": map[string]interface{}{
								"type": "Account",
								"url":  "/services/data/v20.0/sobjects/Account/001D000000IRFmaIAH",
							},
							"Name": "Test 1",
						},
						{
							"attributes": map[string]interface{}{
								"type": "Account",
								"url":  "/services/data/v20.0/sobjects/Account/001D000000IomazIAB",
							},
							"Name": "Test 2",
						},
					},
				},
				records: testNewQueryRecords([]map[string]interface{}{
					{
						"attributes": map[string]interface{}{
							"type": "Account",
							"url":  "/services/data/v20.0/sobjects/Account/001D000000IRFmaIAH",
						},
						"Name": "Test 1",
					},
					{
						"attributes": map[string]interface{}{
							"type": "Account",
							"url":  "/services/data/v20.0/sobjects/Account/001D000000IomazIAB",
						},
						"Name": "Test 2",
					},
				}),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newQueryResult(tt.args.response, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("newQueryResult() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newQueryResult() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryResult_Done(t *testing.T) {
	type fields struct {
		response queryResponse
		records  []*QueryRecord
		resource *Resource
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "Done",
			fields: fields{
				response: queryResponse{
					Done: true,
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &QueryResult{
				response: tt.fields.response,
				records:  tt.fields.records,
				resource: tt.fields.resource,
			}
			if got := result.Done(); got != tt.want {
				t.Errorf("QueryResult.Done() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryResult_TotalSize(t *testing.T) {
	type fields struct {
		response queryResponse
		records  []*QueryRecord
		resource *Resource
	}
	tests := []struct {
		name   string
		fields fields
		want   int
	}{
		{
			name: "Total Size",
			fields: fields{
				response: queryResponse{
					TotalSize: 23,
				},
			},
			want: 23,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &QueryResult{
				response: tt.fields.response,
				records:  tt.fields.records,
				resource: tt.fields.resource,
			}
			if got := result.TotalSize(); got != tt.want {
				t.Errorf("QueryResult.TotalSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryResult_MoreRecords(t *testing.T) {
	type fields struct {
		response queryResponse
		records  []*QueryRecord
		resource *Resource
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "Has More",
			fields: fields{
				response: queryResponse{
					NextRecordsURL: "The Next URL",
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &QueryResult{
				response: tt.fields.response,
				records:  tt.fields.records,
				resource: tt.fields.resource,
			}
			if got := result.MoreRecords(); got != tt.want {
				t.Errorf("QueryResult.MoreRecords() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryResult_Records(t *testing.T) {
	type fields struct {
		response queryResponse
		records  []*QueryRecord
		resource *Resource
	}
	tests := []struct {
		name   string
		fields fields
		want   []*QueryRecord
	}{
		{
			name: "Result Records",
			fields: fields{
				records: testNewQueryRecords([]map[string]interface{}{
					{
						"attributes": map[string]interface{}{
							"type": "Account",
							"url":  "/services/data/v20.0/sobjects/Account/001D000000IRFmaIAH",
						},
						"Name": "Test 1",
					},
					{
						"attributes": map[string]interface{}{
							"type": "Account",
							"url":  "/services/data/v20.0/sobjects/Account/001D000000IomazIAB",
						},
						"Name": "Test 2",
					},
				}),
			},
			want: testNewQueryRecords([]map[string]interface{}{
				{
					"attributes": map[string]interface{}{
						"type": "Account",
						"url":  "/services/data/v20.0/sobjects/Account/001D000000IRFmaIAH",
					},
					"Name": "Test 1",
				},
				{
					"attributes": map[string]interface{}{
						"type": "Account",
						"url":  "/services/data/v20.0/sobjects/Account/001D000000IomazIAB",
					},
					"Name": "Test 2",
				},
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &QueryResult{
				response: tt.fields.response,
				records:  tt.fields.records,
				resource: tt.fields.resource,
			}
			if got := result.Records(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("QueryResult.Records() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryResult_Next(t *testing.T) {
	type fields struct {
		response queryResponse
		records  []*QueryRecord
		resource *Resource
	}
	tests := []struct {
		name    string
		fields  fields
		want    *QueryResult
		wantErr bool
	}{
		{
			name:    "No more records",
			fields:  fields{},
			want:    nil,
			wantErr: true,
		},
		{
			name: "No more records",
			fields: fields{
				response: queryResponse{
					NextRecordsURL: "/services/data/v20.0/query/01gD0000002HU6KIAW-2000",
				},
				resource: &Resource{
					session: &mockSessionFormatter{
						url: "https://test.salesforce.com",
						client: mockHTTPClient(func(req *http.Request) *http.Response {
							if req.URL.String() != "https://test.salesforce.com/services/data/v20.0/query/01gD0000002HU6KIAW-2000" {
								return &http.Response{
									StatusCode: 500,
									Status:     "Some Status",
									Body:       io.NopCloser(strings.NewReader("Error")),
									Header:     make(http.Header),
								}
							}
							resp := `
							{
								"done" : true,
								"totalSize" : 2,
								"records" : 
								[ 
									{  
										"attributes" : 
										{    
											"type" : "Account",    
											"url" : "/services/data/v20.0/sobjects/Account/001D000000IRFmaIAH"  
										},  
										"Name" : "Test 1"
									}, 
									{  
										"attributes" : 
										{    
											"type" : "Account",    
											"url" : "/services/data/v20.0/sobjects/Account/001D000000IomazIAB"  
										},  
										"Name" : "Test 2"
									}
								]
							}`

							return &http.Response{
								StatusCode: 200,
								Body:       io.NopCloser(strings.NewReader(resp)),
								Header:     make(http.Header),
							}
						}),
					},
				},
			},
			want: &QueryResult{
				response: queryResponse{
					Done:      true,
					TotalSize: 2,
					Records: []map[string]interface{}{
						{
							"attributes": map[string]interface{}{
								"type": "Account",
								"url":  "/services/data/v20.0/sobjects/Account/001D000000IRFmaIAH",
							},
							"Name": "Test 1",
						},
						{
							"attributes": map[string]interface{}{
								"type": "Account",
								"url":  "/services/data/v20.0/sobjects/Account/001D000000IomazIAB",
							},
							"Name": "Test 2",
						},
					},
				},
				records: testNewQueryRecords([]map[string]interface{}{
					{
						"attributes": map[string]interface{}{
							"type": "Account",
							"url":  "/services/data/v20.0/sobjects/Account/001D000000IRFmaIAH",
						},
						"Name": "Test 1",
					},
					{
						"attributes": map[string]interface{}{
							"type": "Account",
							"url":  "/services/data/v20.0/sobjects/Account/001D000000IomazIAB",
						},
						"Name": "Test 2",
					},
				}),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &QueryResult{
				response: tt.fields.response,
				records:  tt.fields.records,
				resource: tt.fields.resource,
			}
			got, err := result.Next()
			if (err != nil) != tt.wantErr {
				t.Errorf("QueryResult.Next() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil {
				tt.want.resource = result.resource
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("QueryResult.Next() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryResult_NextReauthenticatesAfterInvalidSessionID(t *testing.T) {
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
	queryCalls := 0
	nextCalls := 0
	var nextAuthHeaders []string

	client := mockHTTPClient(func(req *http.Request) *http.Response {
		switch req.URL.Path {
		case "/services/oauth2/token":
			authCalls++
			token := "expired"
			if authCalls > 1 {
				token = "refreshed"
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"access_token": %q,
					"instance_url": "https://instance.salesforce.example.com",
					"id": "https://test.salesforce.com/id/123456789",
					"token_type": "Bearer",
					"issued_at": "1553568410028",
					"signature": "hello"
				}`, token))),
				Header: make(http.Header),
			}
		case "/services/data/v45.0/query/":
			queryCalls++
			if got, want := req.URL.Query().Get("q"), "SELECT Name FROM Account"; got != want {
				t.Fatalf("query = %q, want %q", got, want)
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(`{
					"done": false,
					"totalSize": 2,
					"nextRecordsUrl": "/services/data/v45.0/query/01gD0000002HU6KIAW-2000",
					"records": [
						{
							"attributes": {
								"type": "Account",
								"url": "/services/data/v45.0/sobjects/Account/001D000000IRFmaIAH"
							},
							"Name": "Test 1"
						}
					]
				}`)),
				Header: make(http.Header),
			}
		case "/services/data/v45.0/query/01gD0000002HU6KIAW-2000":
			nextCalls++
			nextAuthHeaders = append(nextAuthHeaders, req.Header.Get("Authorization"))
			if nextCalls == 1 {
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Status:     "401 Unauthorized",
					Body: io.NopCloser(strings.NewReader(`{
						"message": "Session expired or invalid",
						"errorCode": "INVALID_SESSION_ID"
					}`)),
					Header: make(http.Header),
				}
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(`{
					"done": true,
					"totalSize": 2,
					"records": [
						{
							"attributes": {
								"type": "Account",
								"url": "/services/data/v45.0/sobjects/Account/001D000000IomazIAB"
							},
							"Name": "Test 2"
						}
					]
				}`)),
				Header: make(http.Header),
			}
		default:
			t.Fatalf("unexpected request path %q", req.URL.Path)
			return nil
		}
	})

	sess, err := session.Open(sfdc.Configuration{
		Credentials: passwordCreds,
		Client:      client,
		Version:     45,
	})
	if err != nil {
		t.Fatalf("session.Open() error = %v, want nil", err)
	}

	resource, err := NewResource(sess)
	if err != nil {
		t.Fatalf("NewResource() error = %v, want nil", err)
	}

	result, err := resource.Query(&mockQuerier{stmt: "SELECT Name FROM Account"}, false)
	if err != nil {
		t.Fatalf("Resource.Query() error = %v, want nil", err)
	}
	if !result.MoreRecords() {
		t.Fatal("QueryResult.MoreRecords() = false, want true")
	}

	next, err := result.Next()
	if err != nil {
		t.Fatalf("QueryResult.Next() error = %v, want nil", err)
	}

	if authCalls != 2 {
		t.Fatalf("auth calls = %d, want 2", authCalls)
	}
	if queryCalls != 1 {
		t.Fatalf("query calls = %d, want 1", queryCalls)
	}
	if nextCalls != 2 {
		t.Fatalf("next calls = %d, want 2", nextCalls)
	}
	if !reflect.DeepEqual(nextAuthHeaders, []string{"Bearer expired", "Bearer refreshed"}) {
		t.Fatalf("next authorization headers = %v, want %v", nextAuthHeaders, []string{"Bearer expired", "Bearer refreshed"})
	}
	got, ok := next.Records()[0].Record().FieldValue("Name")
	if !ok {
		t.Fatal("next record field Name missing")
	}
	if want := "Test 2"; got != want {
		t.Fatalf("next record name = %v, want %v", got, want)
	}
}
