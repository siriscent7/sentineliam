package token

import (
	"sync"
	"time"
)

// Denylist tracks revoked token IDs (jti) until their natural expiry.
// A revoked token stays listed only until it would have expired anyway,
// so the list self-cleans and stays bounded.
type Denylist struct {
	mu      sync.Mutex
	revoked map[string]time.Time // jti -> expiry
}

func NewDenylist() *Denylist {
	return &Denylist{revoked: make(map[string]time.Time)}
}

// Revoke marks a token id as revoked until the given expiry time.
func (d *Denylist) Revoke(jti string, expiry time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.revoked[jti] = expiry
}

// IsRevoked reports whether a token id is currently revoked.
// Expired entries are cleaned up lazily on access.
func (d *Denylist) IsRevoked(jti string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	exp, ok := d.revoked[jti]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(d.revoked, jti) // self-clean
		return false
	}
	return true
}

// Size returns the current number of revoked entries (for tests/metrics).
func (d *Denylist) Size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.revoked)
}
