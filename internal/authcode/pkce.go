package authcode

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// VerifyPKCE checks that SHA256(codeVerifier), base64url-encoded, equals the
// stored codeChallenge (the "S256" PKCE method). Uses constant-time comparison.
func VerifyPKCE(codeVerifier, storedChallenge string) bool {
	sum := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	// constant-time comparison to avoid timing leaks
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedChallenge)) == 1
}
