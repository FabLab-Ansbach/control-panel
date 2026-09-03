package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
)

// fakeProvider is a minimal OIDC provider: discovery doc, JWKS, and a /token
// endpoint that echoes back whatever it received (for TokenProxyHandler
// pass-through tests) plus a fixed status/body when tokenResponse is set.
type fakeProvider struct {
	srv         *httptest.Server
	key         *rsa.PrivateKey
	tokenStatus int
	tokenBody   string
	lastReqBody string
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
		body, _ := io.ReadAll(r.Body)
		fp.lastReqBody = string(body)

		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			http.Error(w, "unexpected content-type", http.StatusBadRequest)
			return
		}

		status := fp.tokenStatus
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(fp.tokenBody))
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

func claimsWithTTL(fp *fakeProvider, audience string, groups []string, ttl time.Duration) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":    fp.srv.URL,
		"aud":    audience,
		"sub":    "test-subject",
		"exp":    now.Add(ttl).Unix(),
		"iat":    now.Unix(),
		"groups": groups,
	}
}

const testClientID = "gui-public-client"

func newTestAuthenticator(t *testing.T, fp *fakeProvider) *Authenticator {
	t.Helper()
	auth, err := New(context.Background(), config.OIDCAuthConfig{IssuerURL: fp.srv.URL, ClientID: testClientID})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func TestRequireAuthAcceptsValidBearerToken(t *testing.T) {
	fp := newFakeProvider(t)
	auth := newTestAuthenticator(t, fp)

	token := fp.sign(t, claimsWithTTL(fp, testClientID, []string{"fablab-admins"}, time.Hour))

	var gotGroups []string
	protected := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGroups = GroupsFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/executors", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(gotGroups) != 1 || gotGroups[0] != "fablab-admins" {
		t.Fatalf("groups = %v, want [fablab-admins]", gotGroups)
	}
}

func TestRequireAuthRejectsExpiredToken(t *testing.T) {
	fp := newFakeProvider(t)
	auth := newTestAuthenticator(t, fp)

	expired := fp.sign(t, claimsWithTTL(fp, testClientID, []string{"fablab-admins"}, -time.Minute))
	protected := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/executors", nil)
	req.Header.Set("Authorization", "Bearer "+expired)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// newTestAuthenticatorWithM2M builds an Authenticator with one M2M client
// backed by its own fake provider, mirroring Authentik where each M2M
// client is its own Application/Provider with a distinct issuer.
func newTestAuthenticatorWithM2M(t *testing.T, fp *fakeProvider, m2mFP *fakeProvider, m2mClientID string) *Authenticator {
	t.Helper()
	auth, err := New(context.Background(), config.OIDCAuthConfig{
		IssuerURL: fp.srv.URL,
		ClientID:  testClientID,
		M2MClients: []config.M2MClientConfig{
			{ClientID: m2mClientID, IssuerURL: m2mFP.srv.URL},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func TestRequireAuthAcceptsM2MClientAndExposesItAsAGroup(t *testing.T) {
	fp := newFakeProvider(t)
	m2mFP := newFakeProvider(t)
	auth := newTestAuthenticatorWithM2M(t, fp, m2mFP, "approved-m2m-client")

	token := m2mFP.sign(t, claimsWithTTL(m2mFP, "approved-m2m-client", nil, time.Hour))

	var gotGroups []string
	protected := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGroups = GroupsFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/executors", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(gotGroups) != 1 || gotGroups[0] != "approved-m2m-client" {
		t.Fatalf("groups = %v, want [approved-m2m-client]", gotGroups)
	}
}

func TestRequireAuthRejectsUnapprovedM2MClient(t *testing.T) {
	fp := newFakeProvider(t)
	m2mFP := newFakeProvider(t)
	auth := newTestAuthenticatorWithM2M(t, fp, m2mFP, "approved-m2m-client")

	// Signed by the approved M2M issuer, but for a different client_id -
	// must not be accepted.
	token := m2mFP.sign(t, claimsWithTTL(m2mFP, "some-other-client", nil, time.Hour))
	protected := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/executors", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireAuthRejectsTokenFromUnknownIssuerEvenWithApprovedAudience(t *testing.T) {
	fp := newFakeProvider(t)
	m2mFP := newFakeProvider(t)
	auth := newTestAuthenticatorWithM2M(t, fp, m2mFP, "approved-m2m-client")

	// Signed by some unrelated issuer, with the right audience - must not
	// be accepted; issuer, not just client_id, is what scopes trust.
	otherProvider := newFakeProvider(t)
	token := otherProvider.sign(t, claimsWithTTL(otherProvider, "approved-m2m-client", nil, time.Hour))
	protected := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/executors", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireAuthRejectsWrongAudience(t *testing.T) {
	fp := newFakeProvider(t)
	auth := newTestAuthenticator(t, fp)

	// Validly signed by our own issuer, but minted for some other
	// application - must not be accepted here.
	token := fp.sign(t, claimsWithTTL(fp, "some-other-application", []string{"fablab-admins"}, time.Hour))
	protected := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/executors", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireAuthRejectsTokenFromDifferentIssuer(t *testing.T) {
	fp := newFakeProvider(t)
	auth := newTestAuthenticator(t, fp)

	otherProvider := newFakeProvider(t)
	token := otherProvider.sign(t, claimsWithTTL(otherProvider, "whatever-client", []string{"fablab-admins"}, time.Hour))

	protected := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/executors", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireAuthRejectsNoCredentials(t *testing.T) {
	fp := newFakeProvider(t)
	auth := newTestAuthenticator(t, fp)

	protected := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/executors", nil)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestTokenProxyHandlerForwardsBodyAndReturnsResponse(t *testing.T) {
	fp := newFakeProvider(t)
	auth := newTestAuthenticator(t, fp)
	fp.tokenStatus = http.StatusOK
	fp.tokenBody = `{"access_token":"abc","refresh_token":"def"}`

	reqBody := "grant_type=authorization_code&client_id=gui-public-client&code=xyz&code_verifier=verifier123"
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	auth.TokenProxyHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != fp.tokenBody {
		t.Fatalf("body = %q, want %q (should be an unmodified pass-through)", rec.Body.String(), fp.tokenBody)
	}
	if fp.lastReqBody != reqBody {
		t.Fatalf("authentik received %q, want %q (should forward the request unmodified)", fp.lastReqBody, reqBody)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

func TestTokenProxyHandlerForwardsErrorStatus(t *testing.T) {
	fp := newFakeProvider(t)
	auth := newTestAuthenticator(t, fp)
	fp.tokenStatus = http.StatusBadRequest
	fp.tokenBody = `{"error":"invalid_grant"}`

	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader("grant_type=refresh_token&refresh_token=stale"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	auth.TokenProxyHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (should mirror authentik's status)", rec.Code)
	}
	if rec.Body.String() != fp.tokenBody {
		t.Fatalf("body = %q, want %q", rec.Body.String(), fp.tokenBody)
	}
}

func TestConfigHandlerReportsWhereToAuthenticate(t *testing.T) {
	fp := newFakeProvider(t)
	auth := newTestAuthenticator(t, fp)

	req := httptest.NewRequest(http.MethodGet, "/auth/config", nil)
	rec := httptest.NewRecorder()
	auth.ConfigHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp authConfigResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.AuthorizationEndpoint != fp.srv.URL+"/authorize" {
		t.Errorf("authorizationEndpoint = %q, want %q", resp.AuthorizationEndpoint, fp.srv.URL+"/authorize")
	}
	if resp.TokenEndpoint != "/auth/token" {
		t.Errorf("tokenEndpoint = %q, want /auth/token (our own proxy, not authentik's)", resp.TokenEndpoint)
	}
	if resp.ClientID != testClientID {
		t.Errorf("clientId = %q, want %q", resp.ClientID, testClientID)
	}
}
