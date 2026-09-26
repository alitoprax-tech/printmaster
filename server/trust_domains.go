package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"printmaster/common/requestauth"
)

// Trust domains are application security principals, not merely DNS labels.
// A request gets one immutable principal before it reaches the normal mux; the
// mux and handlers never need to reinterpret Host or forwarded-host headers.
type trustDomain uint8

const (
	trustDomainUnknown trustDomain = iota
	trustDomainShared
	trustDomainAgent
	trustDomainAdmin
	trustDomainPrinterProxy
)

type trustDomainContextKey struct{}

type trustDomainPrincipal struct {
	Domain trustDomain
	Host   string
}

var errUnknownTrustDomain = errors.New("request host is not a configured trust-domain origin")

func trustDomainsConfigured(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	s := cfg.Server
	return s.TrustDomainsEnabled || strings.TrimSpace(s.AgentHost) != "" || strings.TrimSpace(s.AdminHost) != "" || strings.TrimSpace(s.PrinterProxyHost) != "" || strings.TrimSpace(s.AgentExternalURL) != "" || strings.TrimSpace(s.AdminExternalURL) != "" || strings.TrimSpace(s.PrinterProxyExternalURL) != ""
}

func trustDomainsEnforced() bool {
	return trustDomainsConfigured(serverConfig)
}

// validateTrustDomainConfig is intentionally strict. A production operator
// cannot accidentally turn a partial or wildcard configuration into a shared
// origin. Empty values are the explicit local/development compatibility mode.
func validateTrustDomainConfig(cfg *Config) error {
	if !trustDomainsConfigured(cfg) {
		if cfg != nil && !localBindAddress(cfg.Server.BindAddress) {
			return errors.New("non-loopback bind requires explicit agent, admin, and printer-proxy trust domains")
		}
		if cfg != nil && cfg.Server.BrowserProxyEnabled {
			return errors.New("server.browser_proxy_enabled requires trust-domain origins")
		}
		return nil
	}
	if cfg == nil {
		return errors.New("trust-domain configuration is nil")
	}
	if cfg.Server.BehindProxy && !cfg.Server.ProxyUseHTTPS {
		return errors.New("trust-domain mode requires end-to-end TLS; HTTP reverse proxy mode discards the Agent client certificate")
	}
	for _, entry := range cfg.Server.TrustedProxies {
		if strings.TrimSpace(entry) == "*" {
			return errors.New("wildcard trusted proxy is forbidden")
		}
		if _, network, err := net.ParseCIDR(strings.TrimSpace(entry)); err == nil {
			ones, _ := network.Mask.Size()
			if ones == 0 {
				return errors.New("all-addresses trusted proxy CIDR is forbidden")
			}
		}
	}
	if strings.TrimSpace(cfg.Server.AgentHost) == "" || strings.TrimSpace(cfg.Server.AdminHost) == "" || strings.TrimSpace(cfg.Server.PrinterProxyHost) == "" {
		return errors.New("agent_host, admin_host, and printer_proxy_host are all required when trust-domain isolation is enabled")
	}

	hosts := map[trustDomain]string{}
	for domain, raw := range map[trustDomain]string{
		trustDomainAgent:        cfg.Server.AgentHost,
		trustDomainAdmin:        cfg.Server.AdminHost,
		trustDomainPrinterProxy: cfg.Server.PrinterProxyHost,
	} {
		normalized, err := normalizeTrustHost(raw)
		if err != nil {
			return fmt.Errorf("%s host: %w", trustDomainLabel(domain), err)
		}
		hosts[domain] = normalized
	}
	if sameHostname(hosts[trustDomainAgent], hosts[trustDomainAdmin]) || sameHostname(hosts[trustDomainAgent], hosts[trustDomainPrinterProxy]) || sameHostname(hosts[trustDomainAdmin], hosts[trustDomainPrinterProxy]) {
		return errors.New("agent_host, admin_host, and printer_proxy_host must be distinct")
	}

	for domain, raw := range map[trustDomain]string{
		trustDomainAgent:        cfg.Server.AgentExternalURL,
		trustDomainAdmin:        cfg.Server.AdminExternalURL,
		trustDomainPrinterProxy: cfg.Server.PrinterProxyExternalURL,
	} {
		if strings.TrimSpace(raw) == "" {
			continue // The secure https origin is derived from the validated host.
		}
		if _, err := validateTrustExternalURL(raw, hosts[domain]); err != nil {
			return fmt.Errorf("%s external URL: %w", trustDomainLabel(domain), err)
		}
	}
	if cfg.Server.BrowserProxyEnabled && strings.TrimSpace(cfg.Server.PrinterProxyHost) == "" {
		return errors.New("browser proxy requires printer_proxy_host")
	}
	return nil
}

func localBindAddress(raw string) bool {
	if raw == "" || strings.EqualFold(raw, "localhost") {
		return true
	}
	ip := net.ParseIP(raw)
	return ip != nil && ip.IsLoopback()
}

func sameHostname(a, b string) bool {
	ua, _ := url.Parse("//" + a)
	ub, _ := url.Parse("//" + b)
	return strings.EqualFold(ua.Hostname(), ub.Hostname())
}

func trustDomainLabel(domain trustDomain) string {
	switch domain {
	case trustDomainAgent:
		return "agent"
	case trustDomainAdmin:
		return "admin"
	case trustDomainPrinterProxy:
		return "printer-proxy"
	case trustDomainShared:
		return "shared"
	default:
		return "unknown"
	}
}

func normalizeTrustHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("host cannot be empty")
	}
	if strings.ContainsAny(raw, " \t\r\n/?#@\\%") || strings.Contains(raw, "*") {
		return "", errors.New("host must be an exact authority without scheme, path, wildcard, or userinfo")
	}
	if strings.Count(raw, ":") > 1 && !strings.HasPrefix(raw, "[") {
		return "", errors.New("IPv6 hosts must use brackets")
	}
	u, err := url.Parse("//" + raw)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("invalid host authority")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || strings.Contains(host, "*") {
		return "", errors.New("invalid host name")
	}
	if net.ParseIP(host) == nil {
		if len(host) > 253 {
			return "", errors.New("host name too long")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", errors.New("invalid DNS label")
			}
			for _, char := range label {
				if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
					return "", errors.New("invalid DNS character")
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 1 || value > 65535 {
			return "", errors.New("invalid port")
		}
	}
	// Preserve brackets for IPv6 authorities while normalizing case/trailing dot.
	if strings.Contains(host, ":") {
		if u.Port() != "" {
			return "[" + host + "]:" + u.Port(), nil
		}
		return "[" + host + "]", nil
	}
	if u.Port() != "" {
		return host + ":" + u.Port(), nil
	}
	return host, nil
}

func validateTrustExternalURL(raw, expectedHost string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "\r\n\\") {
		return "", errors.New("must be an https origin without credentials, query, or fragment")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", errors.New("must use https in trust-domain mode")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("must not contain a path")
	}
	host, err := normalizeTrustHost(u.Host)
	if err != nil || !strings.EqualFold(host, expectedHost) {
		return "", errors.New("host does not match its configured trust domain")
	}
	return "https://" + expectedHost, nil
}

func configuredTrustHost(cfg *Config, domain trustDomain) string {
	if cfg == nil {
		return ""
	}
	var raw string
	switch domain {
	case trustDomainAgent:
		raw = cfg.Server.AgentHost
	case trustDomainAdmin:
		raw = cfg.Server.AdminHost
	case trustDomainPrinterProxy:
		raw = cfg.Server.PrinterProxyHost
	}
	host, _ := normalizeTrustHost(raw)
	return host
}

func configuredTrustExternalURL(cfg *Config, domain trustDomain) string {
	if cfg == nil {
		return ""
	}
	var raw string
	switch domain {
	case trustDomainAgent:
		raw = cfg.Server.AgentExternalURL
	case trustDomainAdmin:
		raw = cfg.Server.AdminExternalURL
	case trustDomainPrinterProxy:
		raw = cfg.Server.PrinterProxyExternalURL
	}
	host := configuredTrustHost(cfg, domain)
	if raw != "" {
		if value, err := validateTrustExternalURL(raw, host); err == nil {
			return value
		}
	}
	if host != "" {
		return "https://" + host
	}
	return ""
}

func canonicalTrustOrigin(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	host, err := normalizeTrustHost(u.Host)
	if err != nil {
		return "", false
	}
	return strings.ToLower(u.Scheme) + "://" + host, true
}

func trustDomainOrigin(cfg *Config, domain trustDomain) string {
	configured := configuredTrustExternalURL(cfg, domain)
	if origin, ok := canonicalTrustOrigin(configured); ok {
		return origin
	}
	return ""
}

func trustDomainFromContext(r *http.Request) (trustDomainPrincipal, bool) {
	if r == nil {
		return trustDomainPrincipal{}, false
	}
	principal, ok := r.Context().Value(trustDomainContextKey{}).(trustDomainPrincipal)
	return principal, ok && principal.Domain != trustDomainUnknown
}

func requestFromConfiguredTrustedProxy(r *http.Request, cfg *Config) bool {
	if r == nil || cfg == nil || (!cfg.Server.BehindProxy && !cfg.Server.CloudflareProxy) {
		return false
	}
	return isTrustedProxy(extractIPFromAddr(r.RemoteAddr))
}

func canonicalRequestHost(r *http.Request, cfg *Config) string {
	if r == nil {
		return ""
	}
	candidate := strings.TrimSpace(r.Host)
	if requestFromConfiguredTrustedProxy(r, cfg) {
		// The proxy is allowed to supply exactly one canonical host. Direct
		// internet clients cannot influence this branch because their peer is not
		// in the explicit trusted-proxy set.
		// Accept a single value only. Multiple or conflicting forwarding headers
		// cannot select a trust principal.
		values := r.Header.Values("X-Forwarded-Host")
		if len(values) > 1 || r.Header.Get("Forwarded") != "" {
			return ""
		}
		if len(values) == 1 {
			if strings.Contains(values[0], ",") {
				return ""
			}
			candidate = strings.TrimSpace(values[0])
		}
	}
	host, _ := normalizeTrustHost(candidate)
	return host
}

func resolveTrustDomain(cfg *Config, r *http.Request) (trustDomainPrincipal, error) {
	host := canonicalRequestHost(r, cfg)
	if host == "" {
		return trustDomainPrincipal{}, errUnknownTrustDomain
	}
	for domain, configured := range map[trustDomain]string{
		trustDomainAgent:        configuredTrustHost(cfg, trustDomainAgent),
		trustDomainAdmin:        configuredTrustHost(cfg, trustDomainAdmin),
		trustDomainPrinterProxy: configuredTrustHost(cfg, trustDomainPrinterProxy),
	} {
		if configured != "" && strings.EqualFold(configured, host) {
			return trustDomainPrincipal{Domain: domain, Host: host}, nil
		}
	}
	return trustDomainPrincipal{}, errUnknownTrustDomain
}

func routeDomainForPath(path string) trustDomain {
	path = strings.TrimSpace(path)
	// Shared health/version endpoints contain no authenticated or browser state.
	if path == "/health" || path == "/api/version" {
		return trustDomainShared
	}
	// Active customer-network content is confined to the proxy origin.
	if path == "/proxy" || strings.HasPrefix(path, "/proxy/") || strings.HasPrefix(path, "/api/v1/proxy/") {
		return trustDomainPrinterProxy
	}
	// These are the only Agent-plane paths. Exact matching prevents a malformed
	// suffix from falling into the generic human `/api/v1/agents/` handler.
	switch path {
	case "/api/v1/agents/register", "/api/v1/agents/register-with-token", "/api/v1/agents/register-mtls",
		"/api/v1/agents/identity/migrate", "/api/v1/agents/identity/renew", "/api/v1/agents/identity/activate",
		"/api/v1/agents/heartbeat", "/api/v1/agents/device-credentials", "/api/v1/agents/device-auth/start",
		"/api/v1/agents/device-auth/poll", "/api/v1/agents/ws", "/api/v1/agents/update/manifest",
		"/api/v1/agents/update/telemetry", "/api/v1/devices/batch", "/api/v1/metrics/batch",
		"/api/v1/auth/agent-callback/validate":
		return trustDomainAgent
	}
	if strings.HasPrefix(path, "/api/v1/agents/update/download/") {
		return trustDomainAgent
	}
	// All remaining registered routes, including admin Agent operations such as
	// list/command/details/revoke, are human-admin routes by default.
	return trustDomainAdmin
}

func trustDomainOriginAllowed(cfg *Config, principal trustDomainPrincipal, r *http.Request) bool {
	if r == nil {
		return false
	}
	// Cross-origin top-level navigation is needed for OIDC callbacks and the
	// one-use printer ticket. It never carries an unsafe browser method.
	navigation := r.Method == http.MethodGet && r.Header.Get("Origin") == "" && r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document"
	ticketNavigation := principal.Domain == trustDomainPrinterProxy && r.Method == http.MethodGet && r.URL.Query().Has("ticket") && r.Header.Get("Origin") == ""
	if site := r.Header.Get("Sec-Fetch-Site"); (site == "cross-site" || site == "same-site") && !navigation && !ticketNavigation {
		return false
	}
	if navigation || ticketNavigation {
		return true
	}
	expected := trustDomainOrigin(cfg, principal.Domain)
	for _, header := range []string{"Origin", "Referer"} {
		if header == "Referer" && r.Method == http.MethodGet && r.Header.Get("Origin") == "" {
			continue // ordinary external links to a safe admin GET are allowed
		}
		if raw := r.Header.Get(header); raw != "" {
			u, err := url.Parse(raw)
			if err != nil {
				return false
			}
			actual, ok := canonicalTrustOrigin(u.Scheme + "://" + u.Host)
			if !ok || expected == "" || !strings.EqualFold(actual, expected) {
				return false
			}
		}
	}
	if (principal.Domain == trustDomainAdmin || principal.Domain == trustDomainPrinterProxy) && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && r.Header.Get("Origin") == "" && r.Header.Get("Referer") == "" {
		// Cookie-authenticated browser requests must carry a same-origin signal.
		// Native API clients can still authenticate with an explicit bearer token.
		cookieName := adminSessionCookieName()
		if principal.Domain == trustDomainPrinterProxy {
			cookieName = printerProxyCookie
		}
		if _, err := r.Cookie(cookieName); err == nil || r.Header.Get("Sec-Fetch-Site") != "" {
			return false
		}
	}
	return true
}

func trustDomainMiddleware(cfg *Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !trustDomainsConfigured(cfg) {
			next.ServeHTTP(w, r)
			return
		}
		principal, err := resolveTrustDomain(cfg, r)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		routeDomain := routeDomainForPath(r.URL.Path)
		adminProxyRedirect := principal.Domain == trustDomainAdmin && routeDomain == trustDomainPrinterProxy && requestProxyScope(r.URL.Path) != ""
		if routeDomain != trustDomainShared && routeDomain != principal.Domain && !adminProxyRedirect {
			http.NotFound(w, r)
			return
		}
		if !trustDomainOriginAllowed(cfg, principal, r) {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), trustDomainContextKey{}, principal)
		if adminProxyRedirect {
			requireWebAuth(handleAdminProxyRedirect)(w, r.WithContext(ctx))
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requireTrustDomain(r *http.Request, expected trustDomain) error {
	if !trustDomainsEnforced() {
		return nil
	}
	principal, ok := trustDomainFromContext(r)
	if !ok {
		var err error
		principal, err = resolveTrustDomain(serverConfig, r)
		if err != nil {
			return err
		}
	}
	if principal.Domain != expected {
		return fmt.Errorf("request is for %s trust domain", trustDomainLabel(principal.Domain))
	}
	return nil
}

func browserRequestAllowed(r *http.Request) bool {
	if !trustDomainsEnforced() {
		return requestauth.BrowserRequestAllowed(r)
	}
	principal, ok := trustDomainFromContext(r)
	if !ok {
		return false
	}
	if principal.Domain != trustDomainAdmin || !trustDomainOriginAllowed(serverConfig, principal, r) {
		return false
	}
	return true
}

func adminSessionCookieName() string {
	if trustDomainsEnforced() {
		return "__Host-pm_session"
	}
	return "pm_session"
}

func tenantHintCookieNameForRequest() string {
	if trustDomainsEnforced() {
		return "__Host-pm_tenant_hint"
	}
	return "pm_tenant_hint"
}

func oidcStateCookieName() string {
	if trustDomainsEnforced() {
		return "__Host-pm_oidc_state"
	}
	return "printmaster_oidc_state"
}

func secureAdminCookie(r *http.Request) bool {
	if trustDomainsEnforced() {
		return true
	}
	return requestIsHTTPS(r)
}

func adminOriginForRequest(r *http.Request) string {
	if trustDomainsEnforced() {
		return trustDomainOrigin(serverConfig, trustDomainAdmin)
	}
	return ""
}

func canonicalAuthHost(r *http.Request) string {
	if trustDomainsEnforced() {
		if principal, ok := trustDomainFromContext(r); ok && principal.Domain == trustDomainAdmin {
			return principal.Host
		}
		return ""
	}
	return r.Host
}
