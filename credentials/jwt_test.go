package credentials

import (
	"fmt"
	"io"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/elastic/go-sfdc/internal/testkeys"
	"github.com/golang-jwt/jwt/v5"
)

func fixedTime() time.Time {
	return time.Now()
}

func Test_jwtProvider_URL(t *testing.T) {
	tests := []struct {
		name    string
		creds   JwtCredentials
		wantURL string
	}{
		{
			name: "TokenURL provided - should use TokenURL",
			creds: JwtCredentials{
				URL:      "https://login.salesforce.com",
				TokenURL: "https://custom.my.salesforce.com",
			},
			wantURL: "https://custom.my.salesforce.com",
		},
		{
			name: "TokenURL empty - should fall back to URL",
			creds: JwtCredentials{
				URL:      "https://login.salesforce.com",
				TokenURL: "",
			},
			wantURL: "https://login.salesforce.com",
		},
		{
			name: "TokenURL not set - should fall back to URL",
			creds: JwtCredentials{
				URL: "https://test.salesforce.com",
			},
			wantURL: "https://test.salesforce.com",
		},
		{
			name: "Government cloud scenario - different token endpoint",
			creds: JwtCredentials{
				URL:      "https://login.salesforce.com",
				TokenURL: "https://login.salesforce.mil",
			},
			wantURL: "https://login.salesforce.mil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &jwtProvider{
				creds: tt.creds,
			}

			got := provider.URL()
			if got != tt.wantURL {
				t.Errorf("jwtProvider.URL() = %v, want %v", got, tt.wantURL)
			}
		})
	}
}

func Test_jwtProvider_Retrieve(t *testing.T) {
	signKey := testkeys.MustParseRSAPrivateKey(t)

	tests := []struct {
		name          string
		creds         JwtCredentials
		expirationAdj time.Duration
		wantErr       bool
	}{
		{
			name: "Valid Token",
			creds: JwtCredentials{
				URL:            "http://test.password.session",
				ClientId:       "12345",
				ClientUsername: "myusername",
				ClientKey:      signKey,
			},
			expirationAdj: JwtExpiration,
			wantErr:       false,
		},
		{
			name: "Invalid Key",
			creds: JwtCredentials{
				URL:            "http://test.password.session",
				ClientId:       "12345",
				ClientUsername: "myusername",
				ClientKey:      nil,
			},
			expirationAdj: JwtExpiration,
			wantErr:       true,
		},
		{
			name: "Expired Token",
			creds: JwtCredentials{
				URL:            "http://test.password.session",
				ClientId:       "12345",
				ClientUsername: "myusername",
				ClientKey:      signKey,
			},
			expirationAdj: -JwtExpiration,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &jwtProvider{
				creds: tt.creds,
				now:   fixedTime, // Use fixed time for consistency
			}

			expirationTime := fixedTime().Add(tt.expirationAdj)
			_, err := provider.BuildClaimsToken(expirationTime, provider.creds.URL, provider.creds.ClientId, provider.creds.ClientUsername)
			if (err != nil) != tt.wantErr {
				t.Errorf("jwtProvider.BuildClaimsToken() error: %v, wantErr: %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				got, err := provider.Retrieve()
				if err != nil {
					t.Errorf("jwtProvider.Retrieve() error: %v", err)
					return
				}

				b, _ := io.ReadAll(got)

				gotForm, err := url.ParseQuery(string(b))
				if err != nil {
					t.Errorf("Failed to parse got form: %v", err)
					return
				}

				gotToken := gotForm.Get("assertion")
				gotClaims := &jwt.MapClaims{}
				_, err = jwt.ParseWithClaims(gotToken, gotClaims, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return provider.creds.ClientKey.Public(), nil
				})
				if err != nil {
					t.Errorf("Failed to parse got token: %v", err)
					return
				}

				wantClaims := jwt.MapClaims{
					"iss": provider.creds.ClientId,
					"sub": provider.creds.ClientUsername,
					"aud": provider.creds.URL,
					"exp": fixedTime().Add(JwtExpiration).Unix(),
				}

				(*gotClaims)["exp"] = int64((*gotClaims)["exp"].(float64))

				if !reflect.DeepEqual(*gotClaims, wantClaims) {
					t.Errorf("jwtProvider.Retrieve() claims = %v, want %v", gotClaims, wantClaims)
				}
			}
		})
	}
}
