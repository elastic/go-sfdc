package credentials

import (
	"fmt"
	"io"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const SampleKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwCPdYprMz3AMh4CwK8fPdArUL63RMVYoXXYfzFdluW5XYE5m
0a5PuNpMoc33i7+JYGOCS1T+ZhoAM2AHO3/BbC2sB5qNNj48ToR7RADgy+pKyaUa
iks4hWXI2fqzAZR11xFEMkCKl0S7Zn4t/oZkFlXbgI+fxt+ab8+9rXa770pL7yCO
lh5HLIQ1VUPWJN7JeBiKfSnBowGLuelQ8ot7YJmEhohBUN++5ZrfSqPedeLlDYPV
ZLYlEaZE6Xtg0lI+prsJ6wiv0IlTwH7yYECc2XE8MjyWAlNEoObK6kbfD0oIQqU1
oSXkRCp21MHoJ9ZTFJvd+2GArbYTzz0KL/r7TQIDAQABAoIBAQCfXmAnhIyy1pad
4gC+H5qT/tNmxL6KNJOAihTv8eH/P2WcDQu9id64TeFYKDXWpUU2PPN6toHYgGKA
OntlP59Ysj1JhUjxoAd3fO2dRzkuCiSEQrzTznaQNw+0tfu6KMDhZYHySJRryefC
qJBP2Hq2B/rsFLULSLaZXW9PrPdPDxijnq+Mnok8t+1F1LRkhdXAiTAAryLT7V4I
eK6uMd0bHK776dQy7A0hR55B5NOW/1U5iYHhNMNCw31Tct9Ula5Dt5U+oe69xMd5
tog7UaESglsovusN65GpXjwsBUN/a4qYXXUEa3ZWhDsuH3b2ekcMRgfsx5QLSDqH
5nFtX3kFAoGBAPLa4oBmLerzZ68GMU+uKQscN/C8o671UTS7jCbtWcBMUZOGrN3q
+smpB0YB9W4kALSxYM4LsTQ4n8qkfJz1vlMu6iATcPnG+KlEhVITUHXB/ek5aWfZ
N1uZDGUlg0sgWSlubnNs5xl6J8tYGRrk84g5i6QCSYxesoJ+M/1P7yozAoGBAMqK
P/PYkbJWq/gh3KcrbbiQhjz6EoPlypcjBzdfQnPamJ94voh2YYNETlDXTSr5bATP
+dooSaw6lkoDIzZg9IZrq9FDOwXjHptpakpIkYKXKxLVcBl6PrD/hv7jznawdLrP
yWr9nkqIVHvJxMGvjg7ONgJhCuCHmecrO50p4sR/AoGAa/8aqq7FzK3hddvzIdP5
PI+X8N5yi+Nb8W9VrBnwx6sou8owJZ/RVsxsB53nXstz5ObcfcSFUQu9Q4hSQhqm
QKekRg9fNjRdcCiggRdFuJhEKer2DNBz5a/x6yj7cfU4sUwCoiHTw2inOa47u9IE
2pd8mbrKqjmSeKVWyVc6rDECgYAlrp0BYByTQn7SNnKYA4NxYCopdBk3wuvzPIge
LDHv3g6hNNS2DNhNlMrBTZ1EzozjRFJm3TH/whKuCHFnr5gu3h9kWo7DpKLQJUeq
NGAmHLvd0CoAA3dgdNoH2BhUirXc/8WoizEFCuI0+bAKnP/gD0uLG8TrSy8+DBQW
RHG1PwKBgBAsnnjH4KplKrzfMycTczHEM1pll/wWBe38TbA7YjrOYLGJkac0UVVQ
Gqhoj3JfpSlWoUbMrOlyY7FlIptmj71P+xPNThKTcc42KMzYJCPhdMllXWktwWKo
hQZsXUbv/2dzOsyQZWcWM/k+kVArS4+Q3eStBNxaDl0aNQC9CUUg
-----END RSA PRIVATE KEY-----`

func fixedTime() time.Time {
	return time.Now()
}

func Test_jwtProvider_URL(t *testing.T) {
	tests := []struct {
		name     string
		creds    JwtCredentials
		wantURL  string
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
	pemData := []byte(SampleKey)
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("Failed to parse RSA private key: %v", err)
	}

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
