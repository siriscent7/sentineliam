package token

import (
	"strings"
	"testing"
	"time"
)

func newTestIssuer(t *testing.T, ttl time.Duration) *Issuer {
	keys, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return NewIssuer(keys, "test", ttl)
}

func TestIssueAndValidate(t *testing.T) {
	iss := newTestIssuer(t, 15*time.Minute)
	tok, err := iss.Issue("user-1", "read", []string{"admin"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := iss.Validate(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("subject = %s, want user-1", claims.Subject)
	}
	if claims.Scope != "read" {
		t.Errorf("scope = %s, want read", claims.Scope)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin]", claims.Roles)
	}
}

func TestRejectsExpiredToken(t *testing.T) {
	iss := newTestIssuer(t, -1*time.Minute)
	tok, _ := iss.Issue("user-1", "read", nil)
	if _, err := iss.Validate(tok); err == nil {
		t.Error("expected expired token to be rejected")
	}
}

func TestRejectsTamperedToken(t *testing.T) {
	iss := newTestIssuer(t, 15*time.Minute)
	tok, _ := iss.Issue("user-1", "read", nil)

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
	parts[1] = parts[1] + "AAAA" // corrupt the payload -> signature no longer matches
	tampered := strings.Join(parts, ".")

	if _, err := iss.Validate(tampered); err == nil {
		t.Error("expected tampered token to be rejected")
	}
}
