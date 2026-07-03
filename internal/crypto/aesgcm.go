package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// aesGCMEncrypt encrypts plaintext with AES-256-GCM using the given 32-byte key.
// The returned ciphertext has the nonce prepended: nonce || ciphertext+tag.
func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Seal appends the ciphertext+tag to the nonce prefix.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// aesGCMDecrypt reverses aesGCMEncrypt. It verifies the auth tag (tamper detection).
func aesGCMDecrypt(key, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:ns], data[ns:]
	// Open verifies the tag; returns an error if tampered.
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// newRandomKey generates a fresh 32-byte (AES-256) key.
func newRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}
