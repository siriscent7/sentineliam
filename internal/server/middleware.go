package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/anushka/sentineliam/internal/token"
)

// ctxKey is a private type for context keys (avoids collisions).
type ctxKey string

const claimsKey ctxKey = "claims"

// Middleware wraps handlers with authentication + authorization checks.
type Middleware struct {
	issuer *token.Issuer
}

func NewMiddleware(issuer *token.Issuer) *Middleware {
	return &Middleware{issuer: issuer}
}

// Authenticate validates the Bearer token and stores the claims in the request context.
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
			return
		}
		raw := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := m.issuer.Validate(raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return
		}

		// stash claims in the request context for downstream handlers/checks
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole ensures the authenticated caller has the given role.
func (m *Middleware) RequireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFrom(r)
		if claims == nil || !contains(claims.Roles, role) {
			writeError(w, http.StatusForbidden, "insufficient_role", "requires role: "+role)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireScope ensures the token was granted the given scope.
func (m *Middleware) RequireScope(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFrom(r)
		if claims == nil || !contains(strings.Fields(claims.Scope), scope) {
			writeError(w, http.StatusForbidden, "insufficient_scope", "requires scope: "+scope)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// claimsFrom retrieves the validated claims from the request context.
func claimsFrom(r *http.Request) *token.Claims {
	c, _ := r.Context().Value(claimsKey).(*token.Claims)
	return c
}

func contains(list []string, item string) bool {
	for _, x := range list {
		if x == item {
			return true
		}
	}
	return false
}
