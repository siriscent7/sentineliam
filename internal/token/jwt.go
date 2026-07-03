package token

import (
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Issuer signs and validates JWT access tokens using an RSA key pair.
// An optional denylist enables real-time revocation of otherwise-valid tokens.
type Issuer struct {
	keys     *KeyPair
	issuer   string
	ttl      time.Duration
	denylist *Denylist
	kid      string
}

type Claims struct {
	Scope string   `json:"scope,omitempty"`
	Roles []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

func NewIssuer(keys *KeyPair, issuer string, ttl time.Duration) *Issuer {
	return &Issuer{keys: keys, issuer: issuer, ttl: ttl, kid: computeKID(keys.Public)}
}

func (i *Issuer) KID() string { return i.kid }

// WithDenylist attaches a denylist so Validate rejects revoked tokens.
func (i *Issuer) WithDenylist(d *Denylist) *Issuer {
	i.denylist = d
	return i
}

func (i *Issuer) TTL() time.Duration { return i.ttl }

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
	tok.Header["kid"] = i.kid
	return tok.SignedString(i.keys.Private)
}

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
	// revocation check
	if i.denylist != nil && claims.ID != "" && i.denylist.IsRevoked(claims.ID) {
		return nil, errors.New("token has been revoked")
	}
	return claims, nil
}

// ParseUnverifiedClaims extracts claims WITHOUT checking revocation — used by
// /introspect and /revoke, which need the jti/expiry even for a revoked token.
func (i *Issuer) ParseClaimsForIntrospection(tokenString string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return i.keys.Public, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// Public keys accessor (used later by JWKS).
func (i *Issuer) KeyPair() *KeyPair { return i.keys }

func computeKID(pub *rsa.PublicKey) string {
	// A stable key id derived from the modulus (first 8 bytes, hex).
	b := pub.N.Bytes()
	n := 8
	if len(b) < n {
		n = len(b)
	}
	return hex.EncodeToString(b[:n])
}
