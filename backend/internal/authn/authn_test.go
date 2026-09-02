package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
)

// fakeProvider is a minimal OIDC provider: discovery doc, JWKS, and a token
// endpoint that always issues a token for whatever claims the test wants.
type fakeProvider struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	claims map[string]any // claims for the next /token response's id_token
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakeProvider{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 fp.srv.URL,
			"authorization_endpoint": fp.srv.URL + "/authorize",
			"token_endpoint":         fp.srv.URL + "/token",
			"jwks_uri":               fp.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{Key: &fp.key.PublicKey, Algorithm: "RS256", Use: "sig", KeyID: "test-key"}
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idToken := fp.sign(t, fp.claims)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "unused-access-token",
			"id_token":     idToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	fp.srv = httptest.NewServer(mux)
	t.Cleanup(fp.srv.Close)
	return fp
}

func (fp *fakeProvider) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: fp.key}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"kid": "test-key"},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func baseClaims(fp *fakeProvider, audience string, groups []string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":    fp.srv.URL,
		"aud":    audience,
		"sub":    "test-subject",
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"groups": groups,
	}
}

func newTestAuthenticator(t *testing.T, fp *fakeProvider) *Authenticator {
	t.Helper()
	auth, err := New(context.Background(), config.OIDCAuthConfig{
		IssuerURL:    fp.srv.URL,
		ClientID:     "gui-client",
		ClientSecret: "gui-secret",
		RedirectURL:  "http://panel.local/auth/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func TestLoginCallbackEstablishesSession(t *testing.T) {
	fp := newFakeProvider(t)
	auth := newTestAuthenticator(t, fp)
	fp.claims = baseClaims(fp, "gui-client", []string{"fablab-admins"})

	// GET /auth/login
	loginRec := httptest.NewRecorder()
	auth.LoginHandler(loginRec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if loginRec.Code != http.StatusFound {
		t.Fatalf("login status = %d, want %d", loginRec.Code, http.StatusFound)
	}
	loginResp := loginRec.Result()
	redirectURL, err := loginResp.Location()
	if err != nil {
		t.Fatal(err)
	}
	state := redirectURL.Query().Get("state")
	if state == "" {
		t.Fatal("expected state param in authorize redirect")
	}
	var stateCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == stateCookieName {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("expected oauth_state cookie to be set")
	}

	// GET /auth/callback?code=...&state=...
	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/callback?code=test-code&state="+state, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRec := httptest.NewRecorder()
	auth.CallbackHandler(callbackRec, callbackReq)

	callbackResp := callbackRec.Result()
	if callbackResp.StatusCode != http.StatusFound {
		body, _ := json.Marshal(callbackRec.Body.String())
		t.Fatalf("callback status = %d, want %d, body=%s", callbackResp.StatusCode, http.StatusFound, body)
	}
	var sessionCookie *http.Cookie
	for _, c := range callbackResp.Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie to be set")
	}

	// A request carrying the session cookie should authenticate as the GUI user's groups.
	var gotGroups []string
	protected := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGroups = GroupsFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/executors", nil)
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("protected route status = %d, want 200", rec.Code)
	}
	if len(gotGroups) != 1 || gotGroups[0] != "fablab-admins" {
		t.Fatalf("groups = %v, want [fablab-admins]", gotGroups)
	}
}

func TestCallbackRejectsMismatchedState(t *testing.T) {
	fp := newFakeProvider(t)
	auth := newTestAuthenticator(t, fp)
	fp.claims = baseClaims(fp, "gui-client", []string{"fablab-admins"})

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=test-code&state=wrong", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "correct"})
	rec := httptest.NewRecorder()
	auth.CallbackHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRequireAuthBearerToken(t *testing.T) {
	fp := newFakeProvider(t)
	auth := newTestAuthenticator(t, fp)

	var gotGroups []string
	protected := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGroups = GroupsFromContext(r.Context())
	}))

	t.Run("valid m2m token is accepted regardless of audience", func(t *testing.T) {
		token := fp.sign(t, baseClaims(fp, "any-client-registered-in-our-authentik", []string{"fablab-members"}))
		req := httptest.NewRequest(http.MethodGet, "/executors", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if len(gotGroups) != 1 || gotGroups[0] != "fablab-members" {
			t.Fatalf("groups = %v, want [fablab-members]", gotGroups)
		}
	})

	t.Run("token from a different issuer is rejected", func(t *testing.T) {
		otherProvider := newFakeProvider(t)
		token := otherProvider.sign(t, baseClaims(otherProvider, "whatever-client", []string{"fablab-members"}))
		req := httptest.NewRequest(http.MethodGet, "/executors", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("no credentials at all is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/executors", nil)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}
