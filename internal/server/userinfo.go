package server

import "net/http"

// UserInfoHandler is the OIDC /userinfo endpoint. It returns claims about the
// authenticated subject. Must be called with a valid Bearer access token
// (wrap it with the Authenticate middleware).
func UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":   claims.Subject,
		"scope": claims.Scope,
		"roles": claims.Roles,
	})
}
