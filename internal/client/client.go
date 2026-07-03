package client

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// Client is a registered OAuth2 client (a service/application).
type Client struct {
	ID           string
	secretHash   []byte   // bcrypt hash of the client secret
	AllowedScopes []string
	Roles        []string
}

// Registry holds registered clients in memory.
type Registry struct {
	clients map[string]*Client
}

func NewRegistry() *Registry {
	return &Registry{clients: make(map[string]*Client)}
}

// Register adds a client, hashing its secret with bcrypt.
func (r *Registry) Register(id, secret string, scopes, roles []string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	r.clients[id] = &Client{
		ID:            id,
		secretHash:    hash,
		AllowedScopes: scopes,
		Roles:         roles,
	}
	return nil
}

// Authenticate verifies a client's id + secret using constant-time bcrypt comparison.
func (r *Registry) Authenticate(id, secret string) (*Client, error) {
	c, ok := r.clients[id]
	if !ok {
		// Still run a bcrypt comparison against a dummy hash to reduce timing leaks.
		bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinva"), []byte(secret))
		return nil, errors.New("invalid client credentials")
	}
	if err := bcrypt.CompareHashAndPassword(c.secretHash, []byte(secret)); err != nil {
		return nil, errors.New("invalid client credentials")
	}
	return c, nil
}

// ScopeAllowed reports whether the client may request the given scope.
func (c *Client) ScopeAllowed(scope string) bool {
	for _, s := range c.AllowedScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Lookup returns a registered client by id (no secret check).
func (r *Registry) Lookup(id string) (*Client, bool) {
	c, ok := r.clients[id]
	return c, ok
}
