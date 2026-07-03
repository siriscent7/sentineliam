package server

import (
	"net/http"

	"github.com/anushka/sentineliam/internal/refresh"
)

// SetRefreshStore attaches the refresh-token store.
func (s *OAuthServer) SetRefreshStore(r *refresh.Store) {
	s.refresh = r
}

// tokenResponseWithRefresh extends the token response with refresh + ID tokens.
type tokenResponseWithRefresh struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// handleRefreshToken implements the refresh_token grant with rotation + reuse detection.
func (s *OAuthServer) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if s.refresh == nil {
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "refresh not enabled")
		return
	}
	rt := r.PostFormValue("refresh_token")

	result, err := s.refresh.Rotate(rt)
	if err != nil {
		switch err {
		case refresh.ErrReuse:
			writeError(w, http.StatusBadRequest, "invalid_grant",
				"refresh token reuse detected; session revoked")
		default:
			writeError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		}
		return
	}

	access, err := s.issuer.Issue(result.Subject, result.Scope, result.Roles)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	writeJSON(w, http.StatusOK, tokenResponseWithRefresh{
		AccessToken:  access,
		RefreshToken: result.NewRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.issuer.TTL().Seconds()),
		Scope:        result.Scope,
	})
}
