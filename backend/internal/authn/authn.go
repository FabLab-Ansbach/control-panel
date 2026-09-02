package authn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
	"github.com/FabLab-Ansbach/control-panel/internal/reqlog"
)

const (
	sessionCookieName = "session"
	stateCookieName   = "oauth_state"
)

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

// Authenticator handles the GUI's OIDC authorization-code login (confidential
// client, server-side session) and validates bearer JWTs from M2M clients.
type Authenticator struct {
	oauth2Config    oauth2.Config
	idTokenVerifier *oidc.IDTokenVerifier
	bearerVerifier  *oidc.IDTokenVerifier
	sessions        *sessionStore
}

func New(ctx context.Context, cfg config.OIDCAuthConfig) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover oidc provider: %w", err)
	}

	return &Authenticator{
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "groups"},
		},
		idTokenVerifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		bearerVerifier:  provider.Verifier(&oidc.Config{SkipClientIDCheck: true}),
		sessions:        newSessionStore(),
	}, nil
}

// LoginHandler redirects the browser to authentik to start the login flow.
func (a *Authenticator) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state := randomID()
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(5 * time.Minute / time.Second),
	})
	http.Redirect(w, r, a.oauth2Config.AuthCodeURL(state), http.StatusFound)
}

// CallbackHandler exchanges the authorization code (using our client secret),
// verifies the id_token, and starts a server-side session for the caller's groups.
func (a *Authenticator) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil || r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	clearCookie(w, stateCookieName)

	token, err := a.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		slog.ErrorContext(r.Context(), "oidc code exchange failed", "err", err)
		http.Error(w, "token exchange failed", http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		slog.ErrorContext(r.Context(), "token response had no id_token")
		http.Error(w, "no id_token in response", http.StatusUnauthorized)
		return
	}

	idToken, err := a.idTokenVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		slog.ErrorContext(r.Context(), "id_token verification failed", "err", err)
		http.Error(w, "invalid id_token", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Groups []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		slog.ErrorContext(r.Context(), "failed to parse id_token claims", "err", err)
		http.Error(w, "invalid claims", http.StatusUnauthorized)
		return
	}

	reqlog.SetUser(r.Context(), idToken.Subject)

	sessionID := a.sessions.create(claims.Groups, idToken.Subject, time.Until(idToken.Expiry))
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  idToken.Expiry,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// LogoutHandler clears the caller's session.
func (a *Authenticator) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		a.sessions.delete(cookie.Value)
	}
	clearCookie(w, sessionCookieName)
	http.Redirect(w, r, "/", http.StatusFound)
}

// RequireAuth authenticates the caller either via an M2M bearer JWT (any
// validly-signed token from our issuer, authorization is fully group-based)
// or the GUI's session cookie, and puts their groups on the request context.
func (a *Authenticator) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		groups, user, ok := a.authenticate(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		reqlog.SetUser(r.Context(), user)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), groupsCtxKey{}, groups)))
	})
}

func (a *Authenticator) authenticate(r *http.Request) (groups []string, user string, ok bool) {
	if header := r.Header.Get("Authorization"); header != "" {
		return a.authenticateBearer(r.Context(), header)
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, "", false
	}
	return a.sessions.get(cookie.Value)
}

func (a *Authenticator) authenticateBearer(ctx context.Context, header string) (groups []string, user string, ok bool) {
	raw, hasPrefix := strings.CutPrefix(header, "Bearer ")
	if !hasPrefix {
		return nil, "", false
	}

	idToken, err := a.bearerVerifier.Verify(ctx, raw)
	if err != nil {
		slog.ErrorContext(ctx, "bearer token verification failed", "err", err)
		return nil, "", false
	}

	var claims struct {
		Groups []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		slog.ErrorContext(ctx, "failed to parse bearer token claims", "err", err)
		return nil, "", false
	}

	return claims.Groups, idToken.Subject, true
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1})
}

func randomID() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
