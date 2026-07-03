package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/anushka/sentineliam/internal/authcode"
	"github.com/anushka/sentineliam/internal/client"
	"github.com/anushka/sentineliam/internal/token"
)

func introspectServer(t *testing.T) (*OAuthServer, *token.Issuer) {
	keys, err := token.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	denylist := token.NewDenylist()
	issuer := token.NewIssuer(keys, "test", 15*time.Minute).WithDenylist(denylist)
	reg := client.NewRegistry()
	reg.Register("service-a", "s3cr3t", []string{"read"}, []string{"service"})
	codes := authcode.NewStore(60 * time.Second)
	s := NewOAuthServer(reg, issuer, codes)
	s.SetDenylist(denylist)
	return s, issuer
}

func postForm(handler http.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestIntrospectActiveToken(t *testing.T) {
	s, iss := introspectServer(t)
	tok, _ := iss.Issue("user-1", "read", []string{"admin"})

	rec := postForm(s.HandleIntrospect, url.Values{"token": {tok}})
	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["active"] != true {
		t.Errorf("active = %v, want true", resp["active"])
	}
	if resp["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", resp["sub"])
	}
}

func TestIntrospectGarbageIsInactive(t *testing.T) {
	s, _ := introspectServer(t)
	rec := postForm(s.HandleIntrospect, url.Values{"token": {"not.a.token"}})
	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["active"] != false {
		t.Errorf("active = %v, want false for garbage", resp["active"])
	}
}

func TestRevokeThenIntrospectInactive(t *testing.T) {
	s, iss := introspectServer(t)
	tok, _ := iss.Issue("user-1", "read", nil)

	// revoke
	postForm(s.HandleRevoke, url.Values{"token": {tok}})

	// introspect -> inactive
	rec := postForm(s.HandleIntrospect, url.Values{"token": {tok}})
	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["active"] != false {
		t.Errorf("active = %v, want false after revocation", resp["active"])
	}
}

func TestRevokedTokenFailsValidation(t *testing.T) {
	s, iss := introspectServer(t)
	tok, _ := iss.Issue("user-1", "read", nil)

	// still valid before revocation
	if _, err := iss.Validate(tok); err != nil {
		t.Fatalf("token should be valid before revoke: %v", err)
	}

	postForm(s.HandleRevoke, url.Values{"token": {tok}})

	// now Validate should reject it
	if _, err := iss.Validate(tok); err == nil {
		t.Error("expected revoked token to fail validation")
	}
}
