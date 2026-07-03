package token

import (
	"crypto/rand"
	"crypto/rsa"
)

// KeyPair holds the RSA private/public keys used to sign and verify JWTs.
type KeyPair struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

// GenerateKeyPair creates a fresh 2048-bit RSA key pair.
// In production these would be loaded from a secure store, not generated per run.
func GenerateKeyPair() (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &KeyPair{Private: priv, Public: &priv.PublicKey}, nil
}
