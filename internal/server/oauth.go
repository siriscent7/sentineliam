package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/anushka/sentineliam/internal/client"
	"github.com/anushka/sentineliam/internal/token"
)

// OAuthServer handles OAuth2 token requests.
type OAuthServer struct {
	clients *client.Registry
	issuer  *token.Issuer
}

func NewOAuthServer(clients *client.Registry, issuer *token.Issuer) *OAuthServer {
	return &OAuthServer{clients: clients, issuer: issuer}
}

// tokenResponse is the standard OAuth2 success payload.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// errorResponse is the standard OAuth2 error payload.
type errorResponse struct {
	Error       string `json:"error"`
	Description  string `json:"error_description,omitempty"`
}

// HandleToken implements POST /token for the client_credentials grant.
func (s *OAuthServer) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return
	}

	grantType := r.PostFormValue("grant_type")
	if grantType != "client_credentials" {
		writeError(w, http.StatusBadRequest, "unsupported_grant_type",
			"only client_credentials is supported")
		return
	}

	// Credentials can come from the form or HTTP Basic auth.
	clientID, clientSecret := extractClientCredentials(r)
	c, err := s.clients.Authenticate(clientID, clientSecret)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", "authentication failed")
		return
	}

	// Validate requested scopes against what the client is allowed.
	requested := strings.Fields(r.PostFormValue("scope"))
	for _, sc := range requested {
		if !c.ScopeAllowed(sc) {
			writeError(w, http.StatusBadRequest, "invalid_scope",
				"scope not allowed: "+sc)
			return
		}
	}
	grantedScope := strings.Join(requested, " ")

	jwtStr, err := s.issuer.Issue(c.ID, grantedScope, c.Roles)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: jwtStr,
		TokenType:   "Bearer",
		ExpiresIn:   900, // 15 min
		Scope:       grantedScope,
	})
}

func extractClientCredentials(r *http.Request) (string, string) {
	// Prefer HTTP Basic auth (OAuth2 recommended), fall back to form fields.
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	return r.PostFormValue("client_id"), r.PostFormValue("client_secret")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, errorResponse{Error: code, Description: desc})
}
