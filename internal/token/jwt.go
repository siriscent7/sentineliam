package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Issuer signs and validates JWT access tokens using an RSA key pair.
type Issuer struct {
	keys   *KeyPair
	issuer string
	ttl    time.Duration
}

// Claims are the JWT payload: standard registered claims plus our custom fields.
type Claims struct {
	Scope string   `json:"scope,omitempty"`
	Roles []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

func NewIssuer(keys *KeyPair, issuer string, ttl time.Duration) *Issuer {
	return &Issuer{keys: keys, issuer: issuer, ttl: ttl}
}

// Issue creates a signed JWT for the given subject (e.g., client or user id).
func (i *Issuer) Issue(subject, scope string, roles []string) (string, error) {
	now := time.Now()
	claims := Claims{
		Scope: scope,
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
			ID:        randomID(),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return tok.SignedString(i.keys.Private)
}

// Validate parses and verifies a token string, returning its claims if valid.
func (i *Issuer) Validate(tokenString string) (*Claims, error) {
	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return i.keys.Public, nil
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
