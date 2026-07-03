package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/anushka/sentineliam/internal/client"
	"github.com/anushka/sentineliam/internal/token"
)

func testServer(t *testing.T) *OAuthServer {
	keys, err := token.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	issuer := token.NewIssuer(keys, "test", 15*time.Minute)

	reg := client.NewRegistry()
	if err := reg.Register("service-a", "s3cr3t", []string{"read", "write"}, []string{"service"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	return NewOAuthServer(reg, issuer)
}

func postToken(s *OAuthServer, form url.Values, basicUser, basicPass string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	rec := httptest.NewRecorder()
	s.HandleToken(rec, req)
	return rec
}

func TestClientCredentialsSuccess(t *testing.T) {
	s := testServer(t)
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}}
	rec := postToken(s, form, "service-a", "s3cr3t")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var resp tokenResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.AccessToken == "" {
		t.Error("expected an access token")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %s, want Bearer", resp.TokenType)
	}
}

func TestRejectsBadSecret(t *testing.T) {
	s := testServer(t)
	form := url.Values{"grant_type": {"client_credentials"}}
	rec := postToken(s, form, "service-a", "wrong")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRejectsUnknownClient(t *testing.T) {
	s := testServer(t)
	form := url.Values{"grant_type": {"client_credentials"}}
	rec := postToken(s, form, "ghost", "whatever")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRejectsDisallowedScope(t *testing.T) {
	s := testServer(t)
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"admin"}}
	rec := postToken(s, form, "service-a", "s3cr3t")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for disallowed scope", rec.Code)
	}
}

func TestRejectsWrongGrantType(t *testing.T) {
	s := testServer(t)
	form := url.Values{"grant_type": {"password"}}
	rec := postToken(s, form, "service-a", "s3cr3t")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
