package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anushka/sentineliam/internal/token"
)

func mwSetup(t *testing.T) (*Middleware, *token.Issuer) {
	keys, err := token.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	issuer := token.NewIssuer(keys, "test", 15*time.Minute)
	return NewMiddleware(issuer), issuer
}

func requestWithToken(tok string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return req
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestAuthenticateRejectsMissingToken(t *testing.T) {
	mw, _ := mwSetup(t)
	rec := httptest.NewRecorder()
	mw.Authenticate(okHandler()).ServeHTTP(rec, requestWithToken(""))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAuthenticateAcceptsValidToken(t *testing.T) {
	mw, iss := mwSetup(t)
	tok, _ := iss.Issue("user-1", "read", []string{"user"})
	rec := httptest.NewRecorder()
	mw.Authenticate(okHandler()).ServeHTTP(rec, requestWithToken(tok))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRequireRoleAllowsAdmin(t *testing.T) {
	mw, iss := mwSetup(t)
	tok, _ := iss.Issue("user-1", "read", []string{"admin"})
	handler := mw.Authenticate(mw.RequireRole("admin", okHandler()))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithToken(tok))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for admin", rec.Code)
	}
}

func TestRequireRoleBlocksNonAdmin(t *testing.T) {
	mw, iss := mwSetup(t)
	tok, _ := iss.Issue("user-1", "read", []string{"user"})
	handler := mw.Authenticate(mw.RequireRole("admin", okHandler()))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithToken(tok))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for non-admin", rec.Code)
	}
}

func TestRequireScopeEnforced(t *testing.T) {
	mw, iss := mwSetup(t)

	// token WITHOUT write scope -> blocked
	tok, _ := iss.Issue("user-1", "read", nil)
	handler := mw.Authenticate(mw.RequireScope("write", okHandler()))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithToken(tok))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 without write scope", rec.Code)
	}

	// token WITH write scope -> allowed
	tok2, _ := iss.Issue("user-1", "read write", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, requestWithToken(tok2))
	if rec2.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with write scope", rec2.Code)
	}
}
