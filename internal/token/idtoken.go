package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IDClaims are the OIDC ID Token claims: they identify the authenticated user
// to the client application (audience).
type IDClaims struct {
	Nonce string `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

// IssueIDToken creates an OIDC ID token for a user, addressed to a client (audience).
func (i *Issuer) IssueIDToken(subject, clientID, nonce string) (string, error) {
	now := time.Now()
	claims := IDClaims{
		Nonce: nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{clientID}, // the client the token is for
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
			ID:        randomID(),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = i.kid
	return tok.SignedString(i.keys.Private)
}
