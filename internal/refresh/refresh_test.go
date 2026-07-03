package refresh

import (
	"testing"
	"time"
)

func TestRotationIssuesNewToken(t *testing.T) {
	s := NewStore(time.Hour)
	rt := s.Issue("user-1", "read", []string{"user"})

	res, err := s.Rotate(rt)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if res.NewRefreshToken == "" {
		t.Error("expected a new refresh token")
	}
	if res.NewRefreshToken == rt {
		t.Error("rotated token should differ from the old one")
	}
	if res.Subject != "user-1" {
		t.Errorf("subject = %s, want user-1", res.Subject)
	}
}

func TestReuseDetectionRevokesFamily(t *testing.T) {
	s := NewStore(time.Hour)
	rt1 := s.Issue("user-1", "read", nil)

	// legitimate rotation: rt1 -> rt2
	res, err := s.Rotate(rt1)
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	rt2 := res.NewRefreshToken

	// attacker replays the OLD token rt1 -> reuse detected
	if _, err := s.Rotate(rt1); err != ErrReuse {
		t.Fatalf("expected ErrReuse on replay, got %v", err)
	}

	// because the family was revoked, the legitimate rt2 is now also dead
	if _, err := s.Rotate(rt2); err == nil {
		t.Error("expected rt2 to be revoked after family revocation")
	}
}

func TestInvalidTokenRejected(t *testing.T) {
	s := NewStore(time.Hour)
	if _, err := s.Rotate("nonexistent"); err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	s := NewStore(-time.Minute) // already expired
	rt := s.Issue("user-1", "read", nil)
	if _, err := s.Rotate(rt); err != ErrExpired {
		t.Errorf("expected ErrExpired, got %v", err)
	}
}
