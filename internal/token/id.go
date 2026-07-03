package token

import (
	"crypto/rand"
	"encoding/hex"
)

// randomID returns a random 16-byte hex string, used as a JWT ID (jti).
func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
