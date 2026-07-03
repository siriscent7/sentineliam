package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/anushka/sentineliam/internal/authcode"
	"github.com/anushka/sentineliam/internal/client"
	"github.com/anushka/sentineliam/internal/refresh"
	"github.com/anushka/sentineliam/internal/token"
)

// OAuthServer handles OAuth2 authorization + token requests.
type OAuthServer struct {
	clients  *client.Registry
	issuer   *token.Issuer
	codes    *authcode.Store
	denylist *token.Denylist
	refresh  *refresh.Store
}

func NewOAuthServer(clients *client.Registry, issuer *token.Issuer, codes *authcode.Store) *OAuthServer {
	return &OAuthServer{clients: clients, issuer: issuer, codes: codes}
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type errorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// HandleAuthorize implements GET /authorize for the authorization_code flow.
// For this demo, the user is assumed authenticated & consenting (a real IdP
// would render a login + consent page). It issues a code bound to the PKCE
// challenge and redirects back to the client's redirect_uri with ?code=...
func (s *OAuthServer) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	responseType := q.Get("response_type")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	scope := q.Get("scope")
	stateParam := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	if responseType != "code" {
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	}
	if _, ok := s.clients.Lookup(clientID); !ok {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		http.Error(w, "PKCE S256 code_challenge required", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		http.Error(w, "redirect_uri required", http.StatusBadRequest)
		return
	}

	// Demo: assume the logged-in user is "user-123" and has consented.
	code := s.codes.Issue(clientID, "user-123", scope, codeChallenge)

	// Redirect back with the code (and state, echoed for CSRF protection).
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := redirect.Query()
	rq.Set("code", code.Value)
	if stateParam != "" {
		rq.Set("state", stateParam)
	}
	redirect.RawQuery = rq.Encode()

	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// HandleToken dispatches by grant_type.
func (s *OAuthServer) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return
	}

	switch r.PostFormValue("grant_type") {
	case "client_credentials":
		s.handleClientCredentials(w, r)
	case "authorization_code":
		s.handleAuthorizationCode(w, r)
	case "refresh_token":
		s.handleRefreshToken(w, r)
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type",
			"supported: client_credentials, authorization_code")
	}
}

func (s *OAuthServer) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret := extractClientCredentials(r)
	c, err := s.clients.Authenticate(clientID, clientSecret)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", "authentication failed")
		return
	}
	requested := strings.Fields(r.PostFormValue("scope"))
	for _, sc := range requested {
		if !c.ScopeAllowed(sc) {
			writeError(w, http.StatusBadRequest, "invalid_scope", "scope not allowed: "+sc)
			return
		}
	}
	grantedScope := strings.Join(requested, " ")
	issueToken(w, s.issuer, c.ID, grantedScope, c.Roles)
}

func (s *OAuthServer) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	codeValue := r.PostFormValue("code")
	codeVerifier := r.PostFormValue("code_verifier")
	clientID := r.PostFormValue("client_id")

	code, err := s.codes.Consume(codeValue)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	if code.ClientID != clientID {
		writeError(w, http.StatusBadRequest, "invalid_grant", "code was issued to a different client")
		return
	}
	if !authcodeVerify(codeVerifier, code.CodeChallenge) {
		writeError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	roles := []string{}
	if c, ok := s.clients.Lookup(code.ClientID); ok {
		roles = c.Roles
	}
	access, err := s.issuer.Issue(code.UserID, code.Scope, roles)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}
	resp := tokenResponseWithRefresh{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.issuer.TTL().Seconds()),
		Scope:       code.Scope,
	}
	if s.refresh != nil {
		resp.RefreshToken = s.refresh.Issue(code.UserID, code.Scope, roles)
	}
	writeJSON(w, http.StatusOK, resp)
}

// authcodeVerify is a thin wrapper so this file doesn't import authcode twice.
func authcodeVerify(verifier, challenge string) bool {
	return authcode.VerifyPKCE(verifier, challenge)
}

func issueToken(w http.ResponseWriter, issuer *token.Issuer, subject, scope string, roles []string) {
	jwtStr, err := issuer.Issue(subject, scope, roles)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: jwtStr,
		TokenType:   "Bearer",
		ExpiresIn:   900,
		Scope:       scope,
	})
}

func extractClientCredentials(r *http.Request) (string, string) {
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
