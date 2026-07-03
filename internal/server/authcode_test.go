package server

import (
	"crypto/sha256"
	"encoding/base64"
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

func authTestServer(t *testing.T) *OAuthServer {
	keys, err := token.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	issuer := token.NewIssuer(keys, "test", 15*time.Minute)
	reg := client.NewRegistry()
	reg.Register("web-app", "unused", []string{"read", "profile"}, []string{"user"})
	codes := authcode.NewStore(60 * time.Second)
	return NewOAuthServer(reg, issuer, codes)
}

// pkcePair returns a (verifier, S256 challenge) pair.
func pkcePair() (string, string) {
	verifier := "test-verifier-abc123-a-long-random-string"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

func TestFullAuthCodeFlowWithPKCE(t *testing.T) {
	s := authTestServer(t)
	verifier, challenge := pkcePair()

	// Step 1: /authorize -> expect redirect with a code
	authURL := "/authorize?response_type=code&client_id=web-app" +
		"&redirect_uri=" + url.QueryEscape("https://app.example/callback") +
		"&scope=read&state=xyz&code_challenge=" + challenge + "&code_challenge_method=S256"
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	rec := httptest.NewRecorder()
	s.HandleAuthorize(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302 (%s)", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")
	if code == "" {
		t.Fatal("expected a code in the redirect")
	}
	if u.Query().Get("state") != "xyz" {
		t.Error("state not echoed back")
	}

	// Step 2: /token with the code + verifier -> expect an access token
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"web-app"},
		"code_verifier": {verifier},
	}
	tokReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	s.HandleToken(tokRec, tokReq)

	if tokRec.Code != http.StatusOK {
		t.Fatalf("token status = %d, want 200 (%s)", tokRec.Code, tokRec.Body.String())
	}
	var resp tokenResponse
	json.Unmarshal(tokRec.Body.Bytes(), &resp)
	if resp.AccessToken == "" {
		t.Error("expected an access token")
	}
}

func TestPKCEMismatchRejected(t *testing.T) {
	s := authTestServer(t)
	_, challenge := pkcePair()

	authURL := "/authorize?response_type=code&client_id=web-app" +
		"&redirect_uri=" + url.QueryEscape("https://app.example/callback") +
		"&scope=read&code_challenge=" + challenge + "&code_challenge_method=S256"
	rec := httptest.NewRecorder()
	s.HandleAuthorize(rec, httptest.NewRequest(http.MethodGet, authURL, nil))
	code := parseCode(rec)

	// Wrong verifier
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"web-app"},
		"code_verifier": {"WRONG-verifier"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	s.HandleToken(tokRec, req)

	if tokRec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for PKCE mismatch", tokRec.Code)
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	s := authTestServer(t)
	verifier, challenge := pkcePair()

	authURL := "/authorize?response_type=code&client_id=web-app" +
		"&redirect_uri=" + url.QueryEscape("https://app.example/callback") +
		"&scope=read&code_challenge=" + challenge + "&code_challenge_method=S256"
	rec := httptest.NewRecorder()
	s.HandleAuthorize(rec, httptest.NewRequest(http.MethodGet, authURL, nil))
	code := parseCode(rec)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"web-app"},
		"code_verifier": {verifier},
	}
	// First use: OK
	doToken(s, form)
	// Second use: should fail (single-use)
	rec2 := doToken(s, form)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for reused code", rec2.Code)
	}
}

func parseCode(rec *httptest.ResponseRecorder) string {
	u, _ := url.Parse(rec.Header().Get("Location"))
	return u.Query().Get("code")
}

func doToken(s *OAuthServer, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.HandleToken(rec, req)
	return rec
}
