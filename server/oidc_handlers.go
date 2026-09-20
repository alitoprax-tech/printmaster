package main

import (
	context "context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	oidclib "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	webutil "printmaster/common/web"
	authz "printmaster/server/authz"
	"printmaster/server/storage"
)

var (
	oidcCache = struct {
		mu        sync.Mutex
		providers map[string]*oidclib.Provider
	}{providers: make(map[string]*oidclib.Provider)}

	slugPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)
	oidcFlowRate = struct {
		mu      sync.Mutex
		entries map[string]oidcFlowRateEntry
	}{entries: make(map[string]oidcFlowRateEntry)}
	oidcCleanupState = struct {
		mu   sync.Mutex
		last time.Time
	}{}
)

type oidcFlowRateEntry struct {
	windowStart time.Time
	count       int
}

const (
	oidcFlowRateWindow  = time.Minute
	oidcFlowRateLimit   = 20
	oidcFlowRateMaxKeys = 4096
)

func allowOIDCFlow(r *http.Request, operation string) bool {
	key := operation + ":" + getRealIP(r)
	now := time.Now()
	oidcFlowRate.mu.Lock()
	defer oidcFlowRate.mu.Unlock()
	if len(oidcFlowRate.entries) >= oidcFlowRateMaxKeys {
		for existing, entry := range oidcFlowRate.entries {
			if now.Sub(entry.windowStart) >= oidcFlowRateWindow {
				delete(oidcFlowRate.entries, existing)
			}
		}
		if len(oidcFlowRate.entries) >= oidcFlowRateMaxKeys {
			return false
		}
	}
	entry, ok := oidcFlowRate.entries[key]
	if !ok || now.Sub(entry.windowStart) >= oidcFlowRateWindow {
		oidcFlowRate.entries[key] = oidcFlowRateEntry{windowStart: now, count: 1}
		return true
	}
	if entry.count >= oidcFlowRateLimit {
		return false
	}
	entry.count++
	oidcFlowRate.entries[key] = entry
	return true
}

func cleanupOIDCSessions(ctx context.Context) {
	janitor, ok := serverStore.(interface {
		DeleteOIDCSessionsBefore(context.Context, time.Time) (int64, error)
	})
	if !ok {
		return
	}
	oidcCleanupState.mu.Lock()
	if time.Since(oidcCleanupState.last) < time.Minute {
		oidcCleanupState.mu.Unlock()
		return
	}
	oidcCleanupState.last = time.Now()
	oidcCleanupState.mu.Unlock()
	if _, err := janitor.DeleteOIDCSessionsBefore(ctx, time.Now().UTC().Add(-10*time.Minute)); err != nil {
		serverLogger.Warn("OIDC session cleanup failed", "error", err)
	}
}

type oidcClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
}

type oidcProviderPayload struct {
	Slug         string   `json:"slug"`
	DisplayName  string   `json:"display_name"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
	Icon         string   `json:"icon"`
	ButtonText   string   `json:"button_text"`
	ButtonStyle  string   `json:"button_style"`
	AutoLogin    bool     `json:"auto_login"`
	TenantID     string   `json:"tenant_id"`
	DefaultRole  string   `json:"default_role"`
}

func handleAuthOptions(w http.ResponseWriter, r *http.Request) {
	if !allowOIDCFlow(r, "options") {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	ctx := context.Background()
	resolution := resolveTenantForAuthRequest(ctx, r)
	tenantID := ""
	if resolution != nil {
		tenantID = resolution.id
	}

	providers, err := serverStore.ListOIDCProviders(ctx, tenantID)
	if err != nil {
		serverLogger.Error("Failed to load OIDC providers for login", "tenant_id", tenantID, "error", err)
		http.Error(w, "failed to load providers", http.StatusInternalServerError)
		return
	}

	visible := make([]map[string]interface{}, 0, len(providers))
	for _, p := range providers {
		if tenantID == "" {
			if p.TenantID != "" {
				continue
			}
		} else if p.TenantID != "" && p.TenantID != tenantID {
			continue
		}
		visible = append(visible, publicProviderDTO(p))
	}

	resp := map[string]interface{}{
		"local_login": true,
		"providers":   visible,
	}
	if resolution != nil && resolution.id != "" {
		resp["tenant_id"] = resolution.id
		if resolution.name != "" {
			resp["tenant_name"] = resolution.name
		}
		if resolution.source != "" {
			resp["tenant_source"] = resolution.source
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleTenantLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if serverStore == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if !allowOIDCFlow(r, "tenant-lookup") {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	var payload struct {
		Hint string `json:"hint"`
	}
	if err := webutil.DecodeJSONBody(nil, r, &payload, 1<<20); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	ctx := context.Background()
	res := resolveTenantByHintValue(ctx, payload.Hint, "lookup")
	resp := map[string]interface{}{
		"match": false,
	}
	if res != nil && res.id != "" {
		resp["match"] = true
		resp["tenant_id"] = res.id
		if res.name != "" {
			resp["tenant_name"] = res.name
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleOIDCProviders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !authorizeOrReject(w, r, authz.ActionSSOProvidersRead, authz.ResourceRef{}) {
			return
		}
		ctx := context.Background()
		tenantID := strings.TrimSpace(r.URL.Query().Get("tenant"))
		providers, err := serverStore.ListOIDCProviders(ctx, tenantID)
		if err != nil {
			serverLogger.Error("Failed to list OIDC providers", "tenant_id", tenantID, "error", err)
			http.Error(w, "failed to list providers", http.StatusInternalServerError)
			return
		}
		list := make([]map[string]interface{}, 0, len(providers))
		for _, p := range providers {
			list = append(list, adminProviderDTO(p))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		if !authorizeOrReject(w, r, authz.ActionSSOProvidersWrite, authz.ResourceRef{}) {
			return
		}
		var payload oidcProviderPayload
		if err := webutil.DecodeJSONBody(nil, r, &payload, 1<<20); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		provider, err := buildProviderFromPayload(&payload, nil, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ctx := context.Background()
		if err := serverStore.CreateOIDCProvider(ctx, provider); err != nil {
			serverLogger.Error("Failed to create OIDC provider", "slug", provider.Slug, "issuer", provider.Issuer, "error", err)
			http.Error(w, fmt.Sprintf("failed to create provider: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(adminProviderDTO(provider))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleOIDCProvider(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/sso/providers/")
	slug := strings.Trim(rest, "/")
	if slug == "" {
		http.NotFound(w, r)
		return
	}

	ctx := context.Background()
	existing, err := serverStore.GetOIDCProvider(ctx, slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !authorizeOrReject(w, r, authz.ActionSSOProvidersRead, authz.ResourceRef{}) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(adminProviderDTO(existing))
	case http.MethodPut:
		if !authorizeOrReject(w, r, authz.ActionSSOProvidersWrite, authz.ResourceRef{}) {
			return
		}
		var payload oidcProviderPayload
		if err := webutil.DecodeJSONBody(nil, r, &payload, 1<<20); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		updated, err := buildProviderFromPayload(&payload, existing, slug)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := serverStore.UpdateOIDCProvider(ctx, updated); err != nil {
			serverLogger.Error("Failed to update OIDC provider", "slug", slug, "error", err)
			http.Error(w, fmt.Sprintf("failed to update provider: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(adminProviderDTO(updated))
	case http.MethodDelete:
		if !authorizeOrReject(w, r, authz.ActionSSOProvidersWrite, authz.ResourceRef{}) {
			return
		}
		if err := serverStore.DeleteOIDCProvider(ctx, slug); err != nil {
			serverLogger.Error("Failed to delete OIDC provider", "slug", slug, "error", err)
			http.Error(w, fmt.Sprintf("failed to delete provider: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if !allowOIDCFlow(r, "start") {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/auth/oidc/start/")
	slug := strings.Trim(rest, "/")
	if slug == "" {
		http.NotFound(w, r)
		return
	}

	ctx := context.Background()
	cleanupOIDCSessions(ctx)
	provider, err := serverStore.GetOIDCProvider(ctx, slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	effectiveTenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
	if provider.TenantID != "" {
		if effectiveTenant == "" {
			effectiveTenant = provider.TenantID
		} else if effectiveTenant != provider.TenantID {
			serverLogger.Warn("OIDC tenant mismatch attempted", "slug", slug, "provider_tenant", provider.TenantID, "requested_tenant", effectiveTenant)
			http.Error(w, "tenant mismatch", http.StatusForbidden)
			return
		}
	}

	redirectURL := sanitizeRedirectTarget(r.URL.Query().Get("redirect"))
	state, err := randomURLSafe(24)
	if err != nil {
		serverLogger.Error("Failed to generate OIDC state", "slug", slug, "error", err)
		http.Error(w, "failed to create state", http.StatusInternalServerError)
		return
	}
	nonce, err := randomURLSafe(24)
	if err != nil {
		serverLogger.Error("Failed to generate OIDC nonce", "slug", slug, "error", err)
		http.Error(w, "failed to create nonce", http.StatusInternalServerError)
		return
	}

	op, err := cachedOIDCProvider(ctx, provider.Issuer)
	if err != nil {
		serverLogger.Error("Failed to load OIDC issuer", "slug", slug, "issuer", provider.Issuer, "error", err)
		http.Error(w, "failed to load issuer", http.StatusBadGateway)
		return
	}

	oauthConfig := buildOAuthConfig(r, provider, op)

	sess := &storage.OIDCSession{
		ID:           state,
		ProviderSlug: provider.Slug,
		TenantID:     effectiveTenant,
		Nonce:        nonce,
		State:        state,
		RedirectURL:  redirectURL,
		CreatedAt:    time.Now().UTC(),
	}
	if err := serverStore.CreateOIDCSession(ctx, sess); err != nil {
		serverLogger.Error("Failed to persist OIDC session state", "slug", slug, "error", err)
		http.Error(w, "failed to persist state", http.StatusInternalServerError)
		return
	}
	// Bind the one-time state to the browser that initiated the flow. Without
	// this cookie an attacker can complete their own IdP flow and force the
	// callback URL onto another browser (login CSRF/session swapping).
	http.SetCookie(w, &http.Cookie{
		Name:     "printmaster_oidc_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600,
		Secure:   requestIsHTTPS(r),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	authURL := oauthConfig.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	// The callback URL carries the one-time authorization code and state. Do
	// not allow browsers, proxies, or referrers to retain or forward it.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		serverLogger.Warn("OIDC callback missing parameters", "has_state", state != "", "has_code", code != "", "error_param", r.URL.Query().Get("error"), "error_description", r.URL.Query().Get("error_description"))
		http.Redirect(w, r, "/login?error=oidc_invalid", http.StatusFound)
		return
	}

	ctx := context.Background()
	stateCookie, cookieErr := r.Cookie("printmaster_oidc_state")
	if cookieErr != nil || stateCookie == nil || subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(state)) != 1 {
		http.Redirect(w, r, "/login?error=oidc_state", http.StatusFound)
		return
	}
	// Consume the browser binding even when a later provider/token check fails.
	http.SetCookie(w, &http.Cookie{Name: "printmaster_oidc_state", Value: "", Path: "/", MaxAge: -1, Secure: requestIsHTTPS(r), HttpOnly: true, SameSite: http.SameSiteLaxMode})
	sess, err := serverStore.GetOIDCSession(ctx, state)
	if err != nil {
		serverLogger.Warn("OIDC session lookup failed", "state", state[:min(len(state), 16)]+"...", "error", err)
		http.Redirect(w, r, "/login?error=oidc_state", http.StatusFound)
		return
	}
	defer serverStore.DeleteOIDCSession(ctx, sess.ID)
	if sess.CreatedAt.IsZero() || time.Since(sess.CreatedAt) > 10*time.Minute {
		http.Redirect(w, r, "/login?error=oidc_state", http.StatusFound)
		return
	}

	provider, err := serverStore.GetOIDCProvider(ctx, sess.ProviderSlug)
	if err != nil {
		serverLogger.Error("OIDC provider lookup failed", "slug", sess.ProviderSlug, "error", err)
		http.Redirect(w, r, "/login?error=oidc_provider", http.StatusFound)
		return
	}

	op, err := cachedOIDCProvider(ctx, provider.Issuer)
	if err != nil {
		serverLogger.Error("OIDC issuer discovery failed during callback", "slug", provider.Slug, "issuer", provider.Issuer, "error", err)
		http.Redirect(w, r, "/login?error=oidc_discovery", http.StatusFound)
		return
	}

	oauthConfig := buildOAuthConfig(r, provider, op)
	secretHint := maskSecret(provider.ClientSecret)
	serverLogger.Debug("OIDC token exchange starting", "slug", provider.Slug, "redirect_url", oauthConfig.RedirectURL, "token_endpoint", op.Endpoint().TokenURL, "client_id", provider.ClientID, "secret_hint", secretHint)
	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		serverLogger.Error("OIDC token exchange failed", "slug", provider.Slug, "issuer", provider.Issuer, "redirect_url", oauthConfig.RedirectURL, "client_id", provider.ClientID, "secret_hint", secretHint, "error", err)
		http.Redirect(w, r, "/login?error=oidc_exchange", http.StatusFound)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		serverLogger.Error("OIDC response missing id_token", "slug", provider.Slug, "token_type", token.TokenType, "has_access_token", token.AccessToken != "")
		http.Redirect(w, r, "/login?error=oidc_token", http.StatusFound)
		return
	}

	verifier := op.Verifier(&oidclib.Config{ClientID: provider.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		serverLogger.Error("OIDC id_token verification failed", "slug", provider.Slug, "client_id", provider.ClientID, "error", err)
		http.Redirect(w, r, "/login?error=oidc_verify", http.StatusFound)
		return
	}
	if idToken.Nonce != sess.Nonce {
		serverLogger.Warn("OIDC nonce mismatch", "slug", provider.Slug, "expected", sess.Nonce[:min(len(sess.Nonce), 8)]+"...", "got", idToken.Nonce[:min(len(idToken.Nonce), 8)]+"...")
		http.Redirect(w, r, "/login?error=oidc_nonce", http.StatusFound)
		return
	}

	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil {
		serverLogger.Error("OIDC claims parsing failed", "slug", provider.Slug, "subject", idToken.Subject, "error", err)
		http.Redirect(w, r, "/login?error=oidc_claims", http.StatusFound)
		return
	}
	claims.Subject = idToken.Subject

	user, err := resolveOIDCUser(ctx, provider, &claims)
	if err != nil {
		logError("OIDC user resolution failed", "error", err, "provider", provider.Slug)
		http.Redirect(w, r, "/login?error=oidc_user", http.StatusFound)
		return
	}

	if _, err := createSessionCookie(w, r, user.ID); err != nil {
		logError("OIDC session creation failed", "error", err)
		http.Redirect(w, r, "/login?error=oidc_session", http.StatusFound)
		return
	}
	rememberUserTenantHint(w, r, user)

	redirectURL := sess.RedirectURL
	if redirectURL == "" {
		redirectURL = "/"
	}

	// Check if this is an agent callback redirect
	if isAgentCallbackURL(redirectURL) {
		serverLogger.Debug("OIDC callback detected agent redirect", "user_id", user.ID, "callback_url", redirectURL)
		// Generate an agent callback token and append it to the URL
		parsed, parseErr := url.Parse(redirectURL)
		agentID := ""
		if parseErr == nil {
			agentID = strings.TrimSpace(parsed.Query().Get("agent_id"))
		}
		act := generateAgentCallbackToken(user, agentID, redirectURL)
		if act != nil {
			if parseErr == nil {
				q := parsed.Query()
				q.Set("token", act.Token)
				parsed.RawQuery = q.Encode()
				redirectURL = parsed.String()
				serverLogger.Info("OIDC callback injected agent token", "user_id", user.ID, "username", user.Username)
			}
		} else {
			serverLogger.Error("Failed to generate agent callback token during OIDC flow", "user_id", user.ID)
		}
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// isAgentCallbackURL checks if a URL is an agent authentication callback
func isAgentCallbackURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	// OIDC redirect targets are same-origin relative paths. Do not mint a
	// bearer callback token for an arbitrary path or external host.
	return parsed.IsAbs() && strings.EqualFold(parsed.Scheme, "https") && parsed.Host != "" && parsed.User == nil && parsed.Path == "/api/v1/auth/callback" && strings.TrimSpace(parsed.Query().Get("agent_id")) != ""
}

type tenantResolution struct {
	id     string
	name   string
	source string
}

func resolveTenantForAuthRequest(ctx context.Context, r *http.Request) *tenantResolution {
	if serverStore == nil || r == nil {
		return nil
	}
	if value := strings.TrimSpace(r.URL.Query().Get("tenant")); value != "" {
		res := &tenantResolution{id: value, source: "query"}
		res.ensureName(ctx)
		return res
	}
	for _, candidate := range []struct {
		value  string
		source string
	}{
		{r.URL.Query().Get("domain_hint"), "domain_hint"},
		{r.URL.Query().Get("login_hint"), "login_hint"},
	} {
		if res := resolveTenantByHintValue(ctx, candidate.value, candidate.source); res != nil {
			return res
		}
	}
	for _, hostCandidate := range []struct {
		value  string
		source string
	}{
		{r.Host, "host"},
		{firstForwardedHost(r.Header.Get("X-Forwarded-Host")), "forwarded_host"},
	} {
		if res := resolveTenantByHintValue(ctx, hostCandidate.value, hostCandidate.source); res != nil {
			return res
		}
	}
	if c, err := r.Cookie(tenantHintCookieName); err == nil {
		if val := strings.TrimSpace(c.Value); val != "" {
			res := &tenantResolution{id: val, source: "cookie"}
			res.ensureName(ctx)
			return res
		}
	}
	return nil
}

func resolveTenantByHintValue(ctx context.Context, raw, source string) *tenantResolution {
	if serverStore == nil {
		return nil
	}
	norm := storage.NormalizeTenantDomain(raw)
	if norm == "" {
		return nil
	}
	tenant, err := serverStore.FindTenantByDomain(ctx, norm)
	if err != nil || tenant == nil {
		return nil
	}
	return &tenantResolution{id: tenant.ID, name: tenant.Name, source: source}
}

func firstForwardedHost(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if idx := strings.Index(trimmed, ","); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	return trimmed
}

func (tr *tenantResolution) ensureName(ctx context.Context) {
	if tr == nil || tr.name != "" || tr.id == "" || serverStore == nil {
		return
	}
	tenant, err := serverStore.GetTenant(ctx, tr.id)
	if err == nil && tenant != nil {
		tr.name = tenant.Name
	}
}

func adminProviderDTO(p *storage.OIDCProvider) map[string]interface{} {
	return map[string]interface{}{
		"slug":         p.Slug,
		"display_name": p.DisplayName,
		"issuer":       p.Issuer,
		"client_id":    p.ClientID,
		"has_secret":   p.ClientSecret != "",
		"scopes":       p.Scopes,
		"icon":         p.Icon,
		"button_text":  p.ButtonText,
		"button_style": p.ButtonStyle,
		"auto_login":   p.AutoLogin,
		"tenant_id":    p.TenantID,
		"default_role": p.DefaultRole,
		"created_at":   p.CreatedAt,
		"updated_at":   p.UpdatedAt,
	}
}

func publicProviderDTO(p *storage.OIDCProvider) map[string]interface{} {
	return map[string]interface{}{
		"slug":         p.Slug,
		"display_name": p.DisplayName,
		"button_text":  firstNonEmpty(p.ButtonText, p.DisplayName),
		"button_style": p.ButtonStyle,
		"icon":         p.Icon,
		"auto_login":   p.AutoLogin,
		"tenant_id":    p.TenantID,
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func buildProviderFromPayload(payload *oidcProviderPayload, existing *storage.OIDCProvider, forcedSlug string) (*storage.OIDCProvider, error) {
	if payload == nil {
		return nil, fmt.Errorf("payload required")
	}

	result := &storage.OIDCProvider{}
	if existing != nil {
		*result = *existing
	}

	slug := forcedSlug
	if slug == "" {
		slug = strings.ToLower(strings.TrimSpace(payload.Slug))
	}
	if slug == "" {
		slug = slugify(payload.DisplayName)
	}
	slug = strings.TrimSpace(slug)
	if !slugPattern.MatchString(slug) {
		return nil, fmt.Errorf("slug must be 3-64 characters (lowercase letters, numbers, hyphen)")
	}
	result.Slug = slug

	display := strings.TrimSpace(payload.DisplayName)
	if display == "" {
		return nil, fmt.Errorf("display_name required")
	}
	result.DisplayName = display

	issuer := strings.TrimSpace(payload.Issuer)
	if existing == nil && issuer == "" {
		return nil, fmt.Errorf("issuer required")
	}
	if issuer != "" {
		result.Issuer = issuer
	}

	clientID := strings.TrimSpace(payload.ClientID)
	if existing == nil && clientID == "" {
		return nil, fmt.Errorf("client_id required")
	}
	if clientID != "" {
		result.ClientID = clientID
	}

	secret := strings.TrimSpace(payload.ClientSecret)
	if secret != "" {
		result.ClientSecret = secret
	} else if existing == nil {
		return nil, fmt.Errorf("client_secret required")
	}

	result.Scopes = normalizeScopes(payload.Scopes)
	result.Icon = strings.TrimSpace(payload.Icon)
	result.ButtonStyle = strings.TrimSpace(payload.ButtonStyle)
	result.ButtonText = firstNonEmpty(strings.TrimSpace(payload.ButtonText), result.DisplayName)
	result.AutoLogin = payload.AutoLogin
	result.TenantID = strings.TrimSpace(payload.TenantID)

	role := strings.ToLower(strings.TrimSpace(payload.DefaultRole))
	if role != "admin" {
		role = "user"
	}
	result.DefaultRole = storage.NormalizeRole(role)

	return result, nil
}

func slugify(input string) string {
	s := strings.ToLower(strings.TrimSpace(input))
	s = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "provider"
	}
	if len(s) < 3 {
		s = fmt.Sprintf("%s-%s", s, "oidc")
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

func normalizeScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{"openid", "profile", "email"}
	}
	set := map[string]struct{}{}
	for _, scope := range scopes {
		trimmed := strings.TrimSpace(scope)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	set["openid"] = struct{}{}
	ordered := make([]string, 0, len(set))
	if _, ok := set["openid"]; ok {
		ordered = append(ordered, "openid")
		delete(set, "openid")
	}
	for _, candidate := range []string{"profile", "email"} {
		if _, ok := set[candidate]; ok {
			ordered = append(ordered, candidate)
			delete(set, candidate)
		}
	}
	for scope := range set {
		ordered = append(ordered, scope)
	}
	return ordered
}

func cachedOIDCProvider(ctx context.Context, issuer string) (*oidclib.Provider, error) {
	oidcCache.mu.Lock()
	if provider, ok := oidcCache.providers[issuer]; ok {
		oidcCache.mu.Unlock()
		return provider, nil
	}
	oidcCache.mu.Unlock()

	provider, err := oidclib.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	oidcCache.mu.Lock()
	oidcCache.providers[issuer] = provider
	oidcCache.mu.Unlock()
	return provider, nil
}

func buildOAuthConfig(r *http.Request, provider *storage.OIDCProvider, op *oidclib.Provider) *oauth2.Config {
	redirect := buildExternalURL(r) + "/auth/oidc/callback"
	return &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		RedirectURL:  redirect,
		Endpoint:     op.Endpoint(),
		Scopes:       provider.Scopes,
	}
}

func buildExternalURL(r *http.Request) string {
	if serverConfig != nil {
		if configured := strings.TrimRight(strings.TrimSpace(serverConfig.Server.ExternalURL), "/"); configured != "" {
			if parsed, err := url.Parse(configured); err == nil && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && !strings.ContainsAny(configured, "\r\n\\") && strings.EqualFold(parsed.Scheme, "https") {
				return configured
			}
			if serverLogger != nil {
				serverLogger.Warn("Ignoring invalid server.external_url")
			}
		}
	}
	// Host headers are attacker-controlled on a directly exposed server. Use a
	// request host only for loopback development or when the peer is an
	// explicitly trusted reverse proxy; production deployments should set the
	// canonical server.external_url value.
	host := "localhost"
	scheme := "https"
	if r != nil {
		candidate := strings.TrimSpace(r.Host)
		trusted := false
		if hostOnly, _, err := net.SplitHostPort(candidate); err == nil {
			candidate = hostOnly
		}
		if strings.EqualFold(candidate, "localhost") {
			trusted = true
		} else if ip := net.ParseIP(candidate); ip != nil && ip.IsLoopback() {
			trusted = true
		} else if serverConfig != nil && (serverConfig.Server.BehindProxy || serverConfig.Server.CloudflareProxy) {
			trusted = isTrustedProxy(extractIPFromAddr(r.RemoteAddr))
		}
		if trusted && candidate != "" && !strings.ContainsAny(r.Host, "\r\n/@\\") {
			host = r.Host
			if requestIsHTTPS(r) {
				scheme = "https"
			} else {
				scheme = "http"
			}
		}
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func sanitizeRedirectTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	u, err := url.Parse(raw)
	// OIDC callbacks may redirect only within this application. External
	// redirects can turn the login endpoint into an open redirect and can leak
	// an agent callback token to an attacker-controlled host.
	if err != nil || u.IsAbs() || u.Host != "" || u.Scheme != "" || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "\\") || !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

func randomURLSafe(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// maskSecret returns only whether a secret is present and its byte length.
// Secret fragments must never be written to logs because logs are copied to
// central systems and may be retained longer than the credential itself.
func maskSecret(s string) string {
	if s == "" {
		return "(empty)"
	}
	return fmt.Sprintf("set(len=%d)", len(s))
}

func resolveOIDCUser(ctx context.Context, provider *storage.OIDCProvider, claims *oidcClaims) (*storage.User, error) {
	link, err := serverStore.GetOIDCLink(ctx, provider.Slug, claims.Subject)
	if err == nil {
		user, err := serverStore.GetUserByID(ctx, link.UserID)
		if err == nil {
			return user, nil
		}
		// If user was deleted but link still exists, fall through to create new user
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		// Clean up orphaned link
		_ = serverStore.DeleteOIDCLink(ctx, provider.Slug, claims.Subject)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	email := ""
	if claims.EmailVerified {
		email = strings.ToLower(strings.TrimSpace(claims.Email))
	}
	if email != "" {
		user, err := serverStore.GetUserByEmail(ctx, email)
		if err == nil {
			_ = serverStore.CreateOIDCLink(ctx, &storage.OIDCLink{ProviderSlug: provider.Slug, Subject: claims.Subject, Email: email, UserID: user.ID})
			return user, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}

	username := deriveUsername(claims)
	role := provider.DefaultRole
	if role != storage.RoleAdmin && role != storage.RoleOperator {
		role = storage.RoleViewer
	}

	var user *storage.User
	for i := 0; i < 5; i++ {
		candidate := username
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d", username, i)
		}
		candidate = strings.Trim(candidate, "-")
		if candidate == "" {
			candidate = fmt.Sprintf("%s-user", provider.Slug)
		}
		tempUser := &storage.User{
			Username:  candidate,
			Role:      role,
			TenantIDs: []string{},
			Email:     email,
		}
		if provider.TenantID != "" {
			tempUser.TenantIDs = []string{provider.TenantID}
			tempUser.TenantID = provider.TenantID
		}
		pass, err := randomURLSafe(18)
		if err != nil {
			return nil, err
		}
		if err := serverStore.CreateUser(ctx, tempUser, pass); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				continue
			}
			return nil, err
		}
		user = tempUser
		break
	}
	if user == nil {
		return nil, fmt.Errorf("failed to create unique username")
	}

	if err := serverStore.CreateOIDCLink(ctx, &storage.OIDCLink{ProviderSlug: provider.Slug, Subject: claims.Subject, Email: email, UserID: user.ID}); err != nil {
		return nil, err
	}

	logInfo("OIDC auto-provisioned user", "username", user.Username, "provider", provider.Slug, "tenant_id", user.TenantID)

	return user, nil
}

func deriveUsername(claims *oidcClaims) string {
	if claims == nil {
		return "user"
	}
	if claims.PreferredUsername != "" {
		return normalizeUsername(claims.PreferredUsername)
	}
	if claims.Email != "" {
		parts := strings.Split(claims.Email, "@")
		return normalizeUsername(parts[0])
	}
	if claims.Name != "" {
		return normalizeUsername(strings.ReplaceAll(claims.Name, " ", "."))
	}
	return "user"
}

func normalizeUsername(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = regexp.MustCompile(`[^a-z0-9._-]+`).ReplaceAllString(raw, "")
	if raw == "" {
		return "user"
	}
	if len(raw) > 64 {
		raw = raw[:64]
	}
	return raw
}
