package credentials

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const JwtExpiration = 3 * time.Minute

type jwtProvider struct {
	creds JwtCredentials
	now   func() time.Time // Function to get the current time, useful for testing
}

func (provider *jwtProvider) Retrieve() (io.Reader, error) {
	expirationTime := provider.GetAppropriateExpirationTime()
	tokenString, err := provider.BuildClaimsToken(expirationTime, provider.creds.URL, provider.creds.ClientId, provider.creds.ClientUsername)
	if err != nil {
		return nil, fmt.Errorf("jwtProvider.Retrieve() error: %w", err)
	}

	form := url.Values{}
	form.Add("grant_type", string(jwtGrantType))
	form.Add("assertion", tokenString)

	return strings.NewReader(form.Encode()), nil
}

// URL returns the endpoint for the token request.
// If TokenURL is specified, it will be used; otherwise, falls back to URL.
func (provider *jwtProvider) URL() string {
	// Use TokenURL if provided, otherwise fall back to the original URL (audience)
	if provider.creds.TokenURL != "" {
		return provider.creds.TokenURL
	}
	return provider.creds.URL
}

// GetAppropriateExpirationTime returns a time value for the JWT expiration.
func (provider *jwtProvider) GetAppropriateExpirationTime() time.Time {
	if provider.now != nil {
		return provider.now().Add(JwtExpiration)
	}
	return time.Now().Add(JwtExpiration)
}

// BuildClaimsToken generates a signed JWT token with the specified claims.
func (provider *jwtProvider) BuildClaimsToken(expirationTime time.Time, url, clientId, clientUsername string) (string, error) {
	claims := jwt.MapClaims{
		"iss": clientId,
		"sub": clientUsername,
		"aud": url,
		"exp": expirationTime.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	if provider.creds.ClientKey == nil {
		return "", fmt.Errorf("jwtProvider.BuildClaimsToken() error: clientKey is nil")
	}

	tokenString, err := token.SignedString(provider.creds.ClientKey)
	if err != nil {
		return "", fmt.Errorf("jwtProvider.BuildClaimsToken() error: failed to sign token: %w", err)
	}
	return tokenString, nil
}
