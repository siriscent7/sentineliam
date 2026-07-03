package server

import (
	"net/http"
)

// ProfileHandler is an example protected resource that echoes the caller's identity.
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"subject": claims.Subject,
		"scope":   claims.Scope,
		"roles":   claims.Roles,
		"message": "access granted to protected resource",
	})
}

// AdminHandler is a resource that only admins can reach.
func AdminHandler(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"subject": claims.Subject,
		"message": "welcome, admin",
	})
}
