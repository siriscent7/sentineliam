package authcode

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Code is a short-lived, single-use authorization code bound to a client,
// user, requested scope, and a PKCE challenge.
type Code struct {
	Value         string
	ClientID      string
	UserID        string
	Scope         string
	CodeChallenge string // PKCE (S256 hash of the verifier)
	ExpiresAt     time.Time
}

// Store holds outstanding authorization codes (in memory, single-use).
type Store struct {
	mu    sync.Mutex
	codes map[string]*Code
	ttl   time.Duration
}

func NewStore(ttl time.Duration) *Store {
	return &Store{codes: make(map[string]*Code), ttl: ttl}
}

// Issue creates and stores a new authorization code.
func (s *Store) Issue(clientID, userID, scope, codeChallenge string) *Code {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := &Code{
		Value:         randomCode(),
		ClientID:      clientID,
		UserID:        userID,
		Scope:         scope,
		CodeChallenge: codeChallenge,
		ExpiresAt:     time.Now().Add(s.ttl),
	}
	s.codes[c.Value] = c
	return c
}

// Consume atomically fetches and removes a code (single-use), checking expiry.
func (s *Store) Consume(value string) (*Code, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.codes[value]
	if !ok {
		return nil, errors.New("invalid or already-used code")
	}
	delete(s.codes, value) // single-use: remove immediately
	if time.Now().After(c.ExpiresAt) {
		return nil, errors.New("code expired")
	}
	return c, nil
}

func randomCode() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
