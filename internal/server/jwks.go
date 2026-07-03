package server

import (
	"encoding/base64"
	"math/big"
	"net/http"
)

// jwk is a single JSON Web Key (RSA public key) in JWKS format.
type jwk struct {
	Kty string `json:"kty"` // key type: "RSA"
	Use string `json:"use"` // "sig" (signature)
	Alg string `json:"alg"` // "RS256"
	Kid string `json:"kid"` // key id
	N   string `json:"n"`   // modulus (base64url)
	E   string `json:"e"`   // exponent (base64url)
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// HandleJWKS publishes the server's public signing key(s) at /jwks so clients
// can verify tokens. Supports key rotation by listing multiple keys here.
func (s *OAuthServer) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := s.issuer.KeyPair().Public

	// base64url-encode modulus and exponent (no padding), per RFC 7518.
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	set := jwks{Keys: []jwk{{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: s.issuer.KID(),
		N:   n,
		E:   e,
	}}}
	writeJSON(w, http.StatusOK, set)
}
