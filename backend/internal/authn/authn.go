// Package authn makes the backend a pure OIDC resource server: it verifies
// bearer tokens against the issuer's JWKS and reads the caller's groups off
// them. It holds no client secret and no session state — getting and
// refreshing a token is entirely the caller's (frontend's) job.
//
// The frontend does the OIDC Authorization Code + PKCE flow itself (login is
// a top-level browser redirect to authentik, never subject to CORS), but
// authentik in this deployment doesn't send CORS headers on real token
// endpoint responses (only on the OPTIONS preflight), so the frontend can't
// fetch() the token endpoint directly from the browser. TokenProxyHandler is
// a byte-for-byte pass-through of that one request so it becomes a
// server-to-server call instead — no secret involved, nothing inspected or
// stored, just forwarded.
package authn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
	"github.com/FabLab-Ansbach/control-panel/internal/reqlog"
)

// maxTokenRequestBody caps the proxied request body defensively; real token
// requests (code + verifier, or a refresh token) are nowhere near this size.
const maxTokenRequestBody = 1 << 16 // 64KiB

type groupsCtxKey struct{}

// GroupsFromContext returns the groups of the authenticated caller, as put
// there by Authenticator.RequireAuth.
func GroupsFromContext(ctx context.Context) []string {
	groups, _ := ctx.Value(groupsCtxKey{}).([]string)
	return groups
}

// WithGroups returns a context carrying the given groups, as RequireAuth
// would set them. Exposed for tests that exercise authorization without
// going through a full login flow.
func WithGroups(ctx context.Context, groups []string) context.Context {
	return context.WithValue(ctx, groupsCtxKey{}, groups)
}

// tokenSource is one accepted (issuer, client_id) pair. Each Authentik
// Application/Provider issues tokens under its own issuer URL, so the
// frontend and every M2M client get their own verifier rather than sharing
// one — go-oidc checks both issuer and audience for us per verifier.
type tokenSource struct {
	verifier *oidc.IDTokenVerifier
	// m2mClientID is non-empty for an M2M source; a successfully verified
	// token from it is authorized under this client_id, exactly like an
	// OIDC group (M2M tokens carry no `groups` claim of their own).
	m2mClientID string
}

type Authenticator struct {
	sources           []tokenSource
	authorizeEndpoint string
	tokenEndpoint     string
	clientID          string
}

func New(ctx context.Context, cfg config.OIDCAuthConfig) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover oidc provider: %w", err)
	}

	sources := []tokenSource{{verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})}}

	for _, m := range cfg.M2MClients {
		m2mProvider, err := oidc.NewProvider(ctx, m.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("discover oidc provider for m2m client %q: %w", m.ClientID, err)
		}
		sources = append(sources, tokenSource{
			verifier:    m2mProvider.Verifier(&oidc.Config{ClientID: m.ClientID}),
			m2mClientID: m.ClientID,
		})
	}

	return &Authenticator{
		sources:           sources,
		authorizeEndpoint: provider.Endpoint().AuthURL,
		tokenEndpoint:     provider.Endpoint().TokenURL,
		clientID:          cfg.ClientID,
	}, nil
}

type authConfigResponse struct {
	AuthorizationEndpoint string `json:"authorizationEndpoint"`
	TokenEndpoint         string `json:"tokenEndpoint"`
	ClientID              string `json:"clientId"`
}

// ConfigHandler tells a caller where to authenticate and with which
// client_id, so that doesn't have to be hardcoded into every client.
// TokenEndpoint points at our own /auth/token pass-through (see
// TokenProxyHandler), not authentik's directly, since that's what browser
// clients need to use anyway.
func (a *Authenticator) ConfigHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(authConfigResponse{
		AuthorizationEndpoint: a.authorizeEndpoint,
		TokenEndpoint:         "/auth/token",
		ClientID:              a.clientID,
	})
}

// TokenProxyHandler forwards a token request (authorization_code or
// refresh_token grant, PKCE code_verifier included) to authentik's token
// endpoint unmodified, and streams the response straight back. See the
// package doc comment for why this exists.
func (a *Authenticator) TokenProxyHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTokenRequestBody))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, a.tokenEndpoint, bytes.NewReader(body))
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to build token proxy request", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	proxyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		slog.ErrorContext(r.Context(), "token endpoint request failed", "err", err)
		http.Error(w, "token endpoint unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// RequireAuth authenticates the caller via an Authorization: Bearer
// <access_token> header and puts their groups on the request context.
func (a *Authenticator) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		groups, user, ok := a.authenticateBearer(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		reqlog.SetUser(r.Context(), user)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), groupsCtxKey{}, groups)))
	})
}

func (a *Authenticator) authenticateBearer(r *http.Request) (groups []string, user string, ok bool) {
	raw, hasPrefix := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !hasPrefix || raw == "" {
		return nil, "", false
	}

	// Each source is a distinct issuer, so at most one can ever verify a
	// given token; try them in order and keep the last error for logging.
	var lastErr error
	for _, src := range a.sources {
		idToken, err := src.verifier.Verify(r.Context(), raw)
		if err != nil {
			lastErr = err
			continue
		}

		var claims struct {
			Groups []string `json:"groups"`
		}
		if err := idToken.Claims(&claims); err != nil {
			slog.ErrorContext(r.Context(), "failed to parse bearer token claims", "err", err)
			return nil, "", false
		}

		groups = claims.Groups
		if src.m2mClientID != "" {
			// An M2M client has no groups claim; authorize it under its own
			// client_id instead, exactly like an OIDC group (see `permissions`).
			groups = append(groups, src.m2mClientID)
		}
		return groups, idToken.Subject, true
	}

	slog.ErrorContext(r.Context(), "bearer token verification failed", "err", lastErr)
	return nil, "", false
}
