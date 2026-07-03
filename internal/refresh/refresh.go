package refresh

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// state of a refresh token in its lifecycle.
type state int

const (
	active state = iota
	used         // rotated: exchanged for a new token (should never be reused)
	revoked
)

// tokenInfo is the server-side record for one refresh token.
type tokenInfo struct {
	familyID  string
	subject   string
	scope     string
	roles     []string
	state     state
	expiresAt time.Time
}

// Store manages refresh tokens with rotation and reuse detection.
type Store struct {
	mu     sync.Mutex
	tokens map[string]*tokenInfo // refresh token value -> info
	ttl    time.Duration
}

func NewStore(ttl time.Duration) *Store {
	return &Store{tokens: make(map[string]*tokenInfo), ttl: ttl}
}

// Issue creates a brand-new refresh token in a NEW family (e.g., on login).
func (s *Store) Issue(subject, scope string, roles []string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.newToken(randomToken(), subject, scope, roles)
}

// helper (caller holds the lock)
func (s *Store) newToken(familyID, subject, scope string, roles []string) string {
	value := randomToken()
	s.tokens[value] = &tokenInfo{
		familyID:  familyID,
		subject:   subject,
		scope:     scope,
		roles:     roles,
		state:     active,
		expiresAt: time.Now().Add(s.ttl),
	}
	return value
}

// RotateResult is returned by Rotate.
type RotateResult struct {
	NewRefreshToken string
	Subject         string
	Scope           string
	Roles           []string
}

var (
	ErrInvalidToken = errors.New("invalid refresh token")
	ErrExpired      = errors.New("refresh token expired")
	ErrReuse        = errors.New("refresh token reuse detected: family revoked")
)

// Rotate exchanges a refresh token for a new one (rotation).
//   - active token   -> mark used, issue a new token in the same family
//   - used token     -> REUSE DETECTED: revoke the entire family, error
//   - revoked/expired-> error
func (s *Store) Rotate(value string) (*RotateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	info, ok := s.tokens[value]
	if !ok {
		return nil, ErrInvalidToken
	}
	if time.Now().After(info.expiresAt) {
		info.state = revoked
		return nil, ErrExpired
	}

	switch info.state {
	case used:
		// Reuse of an already-rotated token => theft. Revoke the whole family.
		s.revokeFamily(info.familyID)
		return nil, ErrReuse
	case revoked:
		return nil, ErrInvalidToken
	}

	// active: rotate it
	info.state = used
	newToken := s.newToken(info.familyID, info.subject, info.scope, info.roles)

	return &RotateResult{
		NewRefreshToken: newToken,
		Subject:         info.subject,
		Scope:           info.scope,
		Roles:           info.roles,
	}, nil
}

// revokeFamily marks every token sharing the family id as revoked (caller holds lock).
func (s *Store) revokeFamily(familyID string) {
	for _, t := range s.tokens {
		if t.familyID == familyID {
			t.state = revoked
		}
	}
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
