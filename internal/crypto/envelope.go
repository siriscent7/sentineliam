package crypto

import (
	"encoding/base64"
	"encoding/json"
)

// Envelope holds an encrypted payload alongside its encrypted data key.
// Both are base64-encoded for safe storage/transport.
type Envelope struct {
	Ciphertext   string `json:"ciphertext"`    // data encrypted with the DEK
	EncryptedDEK string `json:"encrypted_dek"` // DEK encrypted with the KEK
}

// KeyManager performs envelope encryption using a master key (KEK).
// In production the KEK would live in a KMS/HSM; here it's held in memory.
type KeyManager struct {
	kek []byte // 32-byte master key (Key Encryption Key)
}

// NewKeyManager creates a manager from a 32-byte master key.
func NewKeyManager(masterKey []byte) (*KeyManager, error) {
	if len(masterKey) != 32 {
		return nil, ErrBadKeySize
	}
	return &KeyManager{kek: masterKey}, nil
}

// Encrypt performs envelope encryption:
//  1. generate a fresh DEK
//  2. encrypt the plaintext with the DEK (AES-256-GCM)
//  3. encrypt the DEK with the KEK
//  4. return both, base64-encoded
func (km *KeyManager) Encrypt(plaintext []byte) (*Envelope, error) {
	dek, err := newRandomKey()
	if err != nil {
		return nil, err
	}
	ciphertext, err := aesGCMEncrypt(dek, plaintext)
	if err != nil {
		return nil, err
	}
	encryptedDEK, err := aesGCMEncrypt(km.kek, dek)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
		EncryptedDEK: base64.StdEncoding.EncodeToString(encryptedDEK),
	}, nil
}

// Decrypt reverses Encrypt: unwrap the DEK with the KEK, then decrypt the data.
func (km *KeyManager) Decrypt(env *Envelope) ([]byte, error) {
	encryptedDEK, err := base64.StdEncoding.DecodeString(env.EncryptedDEK)
	if err != nil {
		return nil, err
	}
	dek, err := aesGCMDecrypt(km.kek, encryptedDEK)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	return aesGCMDecrypt(dek, ciphertext)
}

// Marshal/Unmarshal for storing an envelope as JSON.
func (e *Envelope) Marshal() ([]byte, error)    { return json.Marshal(e) }
func Unmarshal(data []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}
