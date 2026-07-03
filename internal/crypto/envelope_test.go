package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func newKM(t *testing.T) *KeyManager {
	kek := make([]byte, 32)
	io.ReadFull(rand.Reader, kek)
	km, err := NewKeyManager(kek)
	if err != nil {
		t.Fatalf("key manager: %v", err)
	}
	return km
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	km := newKM(t)
	plaintext := []byte("my-secret-value")

	env, err := km.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if env.Ciphertext == "" || env.EncryptedDEK == "" {
		t.Fatal("envelope missing fields")
	}

	got, err := km.Decrypt(env)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip = %q, want %q", got, plaintext)
	}
}

func TestEachEncryptionUsesFreshDEK(t *testing.T) {
	km := newKM(t)
	e1, _ := km.Encrypt([]byte("same"))
	e2, _ := km.Encrypt([]byte("same"))
	// Same plaintext, but different DEK + nonce -> different ciphertext each time.
	if e1.Ciphertext == e2.Ciphertext {
		t.Error("expected different ciphertext for repeated encryption (fresh DEK/nonce)")
	}
	if e1.EncryptedDEK == e2.EncryptedDEK {
		t.Error("expected a fresh DEK per encryption")
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	km := newKM(t)
	env, _ := km.Encrypt([]byte("secret"))
	env.Ciphertext = "AAAA" + env.Ciphertext[4:] // corrupt
	if _, err := km.Decrypt(env); err == nil {
		t.Error("expected tampered ciphertext to be rejected (GCM auth tag)")
	}
}

func TestWrongKEKCannotDecrypt(t *testing.T) {
	km1 := newKM(t)
	km2 := newKM(t) // different master key
	env, _ := km1.Encrypt([]byte("secret"))
	if _, err := km2.Decrypt(env); err == nil {
		t.Error("expected decryption with the wrong KEK to fail")
	}
}

func TestRejectsBadKeySize(t *testing.T) {
	if _, err := NewKeyManager([]byte("too-short")); err == nil {
		t.Error("expected error for non-32-byte master key")
	}
}
