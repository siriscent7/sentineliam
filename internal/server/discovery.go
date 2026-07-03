package server

import (
	"net/http"
)

// HandleDiscovery serves the OIDC discovery document at
// /.well-known/openid-configuration, describing endpoints and capabilities.
func (s *OAuthServer) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	base := "http://" + r.Host
	doc := map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"introspection_endpoint":                base + "/introspect",
		"revocation_endpoint":                   base + "/revoke",
		"jwks_uri":                              base + "/jwks",
		"userinfo_endpoint":                     base + "/userinfo",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "read", "write", "profile"},
	}
	writeJSON(w, http.StatusOK, doc)
}
