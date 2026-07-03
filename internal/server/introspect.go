package server

import (
	"net/http"
	"time"

	"github.com/anushka/sentineliam/internal/token"
)

// SetDenylist attaches a denylist to the server (used by /revoke + /introspect).
func (s *OAuthServer) SetDenylist(d *token.Denylist) {
	s.denylist = d
}

// HandleIntrospect implements POST /introspect (RFC 7662).
// Returns {"active": true, ...claims} for valid non-revoked tokens, else {"active": false}.
func (s *OAuthServer) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	r.ParseForm()
	tok := r.PostFormValue("token")

	claims, err := s.issuer.ParseClaimsForIntrospection(tok)
	if err != nil {
		// unparseable/expired/tampered -> inactive (never leak details)
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	if s.denylist != nil && claims.ID != "" && s.denylist.IsRevoked(claims.ID) {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"active":  true,
		"sub":     claims.Subject,
		"scope":   claims.Scope,
		"roles":   claims.Roles,
		"iss":     claims.Issuer,
		"jti":     claims.ID,
		"exp":     claims.ExpiresAt.Unix(),
	})
}

// HandleRevoke implements POST /revoke (RFC 7009).
// Adds the token's jti to the denylist until its natural expiry.
func (s *OAuthServer) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	r.ParseForm()
	tok := r.PostFormValue("token")

	claims, err := s.issuer.ParseClaimsForIntrospection(tok)
	if err != nil {
		// RFC 7009: revoking an invalid token still returns 200 (idempotent).
		w.WriteHeader(http.StatusOK)
		return
	}
	if s.denylist != nil && claims.ID != "" {
		expiry := time.Now().Add(time.Hour) // fallback
		if claims.ExpiresAt != nil {
			expiry = claims.ExpiresAt.Time
		}
		s.denylist.Revoke(claims.ID, expiry)
	}
	w.WriteHeader(http.StatusOK)
}
