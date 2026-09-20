package tenancy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	authz "printmaster/server/authz"
	"printmaster/server/email"
	"printmaster/server/storage"

	"printmaster/common/logger"
	webutil "printmaster/common/web"
)

func buildTenancyExternalURL(r *http.Request) string {
	if externalURLBuilder != nil {
		if value := strings.TrimRight(strings.TrimSpace(externalURLBuilder(r)), "/"); value != "" {
			return value
		}
	}
	host := "localhost"
	if r != nil {
		candidate := strings.TrimSpace(r.Host)
		if hostOnly, _, err := net.SplitHostPort(candidate); err == nil {
			candidate = hostOnly
		}
		if strings.EqualFold(candidate, "localhost") || (net.ParseIP(candidate) != nil && net.ParseIP(candidate).IsLoopback()) {
			if !strings.ContainsAny(r.Host, "\r\n/@\\") {
				host = r.Host
			}
		}
	}
	return "https://" + host
}

// RegisterRoutes registers HTTP handlers for tenancy endpoints.
// dbStore, when set via RegisterRoutes, will be used for persistence. If nil,
// the package in-memory `store` is used (keeps tests and backwards compatibility).
var dbStore storage.Store

// tenancyEnabled controls whether administrator-facing tenancy features
// (tenant CRUD, join tokens, package generation) are active. The public
// token registration endpoint remains reachable even when disabled so
// agents can always onboard via the new flow.
var tenancyEnabled bool

// agentBearerEnrollmentEnabled is controlled by the server's P0-01 rollout
// mode. Existing installs keep it enabled; mtls mode rejects new bearer
// enrollment even though the legacy route remains registered for compatibility.
var agentBearerEnrollmentEnabled = true

// pkgLogger provides structured logging for the tenancy package.
var pkgLogger *logger.Logger

// SetLogger configures the structured logger for the tenancy package.
func SetLogger(l *logger.Logger) {
	pkgLogger = l
}

func logDebug(msg string, kv ...interface{}) {
	if pkgLogger != nil {
		pkgLogger.Debug(msg, kv...)
	}
}

func logInfo(msg string, kv ...interface{}) {
	if pkgLogger != nil {
		pkgLogger.Info(msg, kv...)
	}
}

func logWarn(msg string, kv ...interface{}) {
	if pkgLogger != nil {
		pkgLogger.Warn(msg, kv...)
	}
}

func logError(msg string, kv ...interface{}) {
	if pkgLogger != nil {
		pkgLogger.Error(msg, kv...)
	}
}

// SetEnabled allows the main server to toggle tenancy feature flags at
// runtime (typically at startup based on configuration).
func SetEnabled(enabled bool) {
	tenancyEnabled = enabled
}

func SetAgentBearerEnrollmentEnabled(enabled bool) {
	agentBearerEnrollmentEnabled = enabled
}

// IsEnabled returns whether tenancy features are currently enabled.
func IsEnabled() bool {
	return tenancyEnabled
}

// agentEventSink, when configured, receives lifecycle events so the server can fan out
// updates (e.g., via SSE) to the UI without this package importing higher layers.
var agentEventSink func(eventType string, data map[string]interface{})

var agentSettingsBuilder func(context.Context, string, string) (string, interface{}, error)

var auditLogger func(*http.Request, *storage.AuditEntry)

// emailSender, when configured, sends themed HTML emails for agent deployment.
// Parameters: to, subject, htmlBody, textBody; returns error.
var emailSender func(to, subject, htmlBody, textBody string) error

// emailThemeGetter, when configured, returns the configured email theme.
var emailThemeGetter func() string

// externalURLBuilder is supplied by the server so generated bootstrap links
// use the configured canonical URL rather than an untrusted Host header.
var externalURLBuilder func(*http.Request) string

// getUserFromContext, when configured, retrieves the current user from request context.
var getUserFromContext func(ctx context.Context) *storage.User

var (
	defaultReleaseAssetBaseURL = "https://github.com/mstrhakr/printmaster/releases/download"
	releaseAssetBaseURL        = defaultReleaseAssetBaseURL
	releaseDownloadClient      = &http.Client{Timeout: 2 * time.Minute, CheckRedirect: checkReleaseRedirect}
)

const (
	maxAgentDownloadBytes       int64 = 256 << 20
	maxConcurrentAgentDownloads       = 4
)

var agentDownloadSlots = make(chan struct{}, maxConcurrentAgentDownloads)

// checkReleaseRedirect keeps the download proxy on GitHub's HTTPS release
// infrastructure. The initial URL is fixed, but release assets legitimately
// redirect to GitHub's CDN; following an arbitrary Location would reintroduce
// SSRF and allow a compromised upstream to target private network services.
func checkReleaseRedirect(req *http.Request, via []*http.Request) error {
	if req == nil || req.URL == nil || !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("release redirect must use HTTPS")
	}
	host := strings.ToLower(strings.TrimSuffix(req.URL.Hostname(), "."))
	if host != "github.com" && host != "githubusercontent.com" &&
		!strings.HasSuffix(host, ".github.com") && !strings.HasSuffix(host, ".githubusercontent.com") {
		return fmt.Errorf("release redirect host is not trusted")
	}
	if len(via) >= 5 {
		return fmt.Errorf("too many release redirects")
	}
	return nil
}

func acquireAgentDownload(ctx context.Context) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case agentDownloadSlots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func releaseAgentDownload() {
	select {
	case <-agentDownloadSlots:
	default:
	}
}

type enrollmentRateEntry struct {
	windowStart time.Time
	count       int
}

var publicEnrollmentRate = struct {
	sync.Mutex
	entries map[string]enrollmentRateEntry
}{entries: make(map[string]enrollmentRateEntry)}

// Argon2 verification is intentionally expensive. A small process-wide slot
// pool prevents a distributed flood of valid-looking enrollment requests from
// consuming unbounded memory/CPU even when each source IP stays below its
// individual rate limit.
var publicEnrollmentSlots = make(chan struct{}, 4)

const (
	publicEnrollmentWindow  = time.Minute
	publicEnrollmentLimit   = 20
	publicEnrollmentMaxKeys = 4096
)

func publicEnrollmentKey(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	if remote := strings.TrimSpace(r.RemoteAddr); remote != "" {
		return remote
	}
	return "unknown"
}

// allowPublicEnrollment bounds the Argon2 work and pending-row creation on
// the unauthenticated enrollment endpoint.  The map is capped and expired
// entries are evicted so attacker-controlled IPs cannot grow it forever.
func allowPublicEnrollment(r *http.Request) bool {
	now := time.Now().UTC()
	key := publicEnrollmentKey(r)
	publicEnrollmentRate.Lock()
	defer publicEnrollmentRate.Unlock()
	for k, entry := range publicEnrollmentRate.entries {
		if now.Sub(entry.windowStart) >= publicEnrollmentWindow {
			delete(publicEnrollmentRate.entries, k)
		}
	}
	entry, ok := publicEnrollmentRate.entries[key]
	if !ok || now.Sub(entry.windowStart) >= publicEnrollmentWindow {
		if len(publicEnrollmentRate.entries) >= publicEnrollmentMaxKeys {
			return false
		}
		publicEnrollmentRate.entries[key] = enrollmentRateEntry{windowStart: now, count: 1}
		return true
	}
	if entry.count >= publicEnrollmentLimit {
		return false
	}
	entry.count++
	publicEnrollmentRate.entries[key] = entry
	return true
}

// requestTenantAccess returns the tenant scope carried by the authenticated
// web user. Pending registrations are indexed by the tenant of the expired
// token, so every read or mutation must use this scope before touching the
// record.
func requestTenantAccess(r *http.Request) (*storage.User, map[string]struct{}, bool) {
	if getUserFromContext == nil {
		return nil, nil, false
	}
	u := getUserFromContext(r.Context())
	if u == nil {
		return nil, nil, false
	}
	if storage.NormalizeRole(string(u.Role)) == storage.RoleAdmin {
		return u, nil, true
	}
	ids := append([]string{}, u.TenantIDs...)
	if len(ids) == 0 && strings.TrimSpace(u.TenantID) != "" {
		ids = []string{strings.TrimSpace(u.TenantID)}
	}
	allowed := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			allowed[id] = struct{}{}
		}
	}
	return u, allowed, len(allowed) > 0
}

func pendingTenantAllowed(allowed map[string]struct{}, admin bool, tenantID string) bool {
	if admin {
		return true
	}
	_, ok := allowed[strings.TrimSpace(tenantID)]
	return ok
}

// SetAgentEventSink registers a callback invoked for agent lifecycle events.
func SetAgentEventSink(sink func(eventType string, data map[string]interface{})) {
	agentEventSink = sink
}

// SetAgentSettingsBuilder wires the callback that produces resolved settings snapshots for agents.
func SetAgentSettingsBuilder(builder func(context.Context, string, string) (string, interface{}, error)) {
	agentSettingsBuilder = builder
}

// SetAuditLogger wires an audit sink so tenancy actions appear in the central audit log.
func SetAuditLogger(logger func(*http.Request, *storage.AuditEntry)) {
	auditLogger = logger
}

// SetEmailSender wires the function used to send themed HTML emails for agent deployment.
func SetEmailSender(sender func(to, subject, htmlBody, textBody string) error) {
	emailSender = sender
}

// SetEmailThemeGetter wires the function that returns the configured email theme.
func SetEmailThemeGetter(getter func() string) {
	emailThemeGetter = getter
}

func SetExternalURLBuilder(builder func(*http.Request) string) {
	externalURLBuilder = builder
}

// SetUserFromContextGetter wires the function that retrieves the current user from context.
func SetUserFromContextGetter(getter func(ctx context.Context) *storage.User) {
	getUserFromContext = getter
}

// tenantCreatedCallback, when set, is invoked after a new tenant is created.
// This allows the main package to perform setup like creating INIT_SECRET join tokens.
var tenantCreatedCallback func(ctx context.Context, tenantID string)

// SetTenantCreatedCallback registers a callback to be invoked when a new tenant is created.
func SetTenantCreatedCallback(cb func(ctx context.Context, tenantID string)) {
	tenantCreatedCallback = cb
}

// generateDeploymentEmail generates HTML and text versions of the deployment email.
func generateDeploymentEmail(theme, recipientEmail, platform, oneLiner, script, downloadURL, expiresIn, tenantName, serverURL, senderName string) (string, string, error) {
	data := email.AgentDeploymentEmailData{
		RecipientEmail: recipientEmail,
		Platform:       platform,
		OneLiner:       oneLiner,
		Script:         script,
		DownloadURL:    downloadURL,
		ExpiresIn:      expiresIn,
		TenantName:     tenantName,
		ServerURL:      serverURL,
		SentBy:         senderName,
	}
	return email.GenerateAgentDeploymentEmail(email.NormalizeTheme(theme), data)
}

func recordAudit(r *http.Request, entry *storage.AuditEntry) {
	if auditLogger == nil || entry == nil {
		return
	}
	auditLogger(r, entry)
}

func maskTokenValue(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if len(token) <= 8 {
		return "[redacted]"
	}
	return token[:4] + "..." + token[len(token)-2:]
}

func tenantAuditMetadata(name, description, contactName, contactEmail, contactPhone, businessUnit, billingCode, address, loginDomain string) map[string]interface{} {
	return map[string]interface{}{
		"name":          name,
		"description":   description,
		"contact_name":  contactName,
		"contact_email": contactEmail,
		"contact_phone": contactPhone,
		"business_unit": businessUnit,
		"billing_code":  billingCode,
		"address":       address,
		"login_domain":  storage.NormalizeTenantDomain(loginDomain),
	}
}

func attachAgentSettings(resp map[string]interface{}, ctx context.Context, tenantID string, agentID string) {
	if agentSettingsBuilder == nil || resp == nil {
		return
	}
	version, snapshot, err := agentSettingsBuilder(ctx, tenantID, agentID)
	if err != nil || version == "" || snapshot == nil {
		return
	}
	resp["settings_version"] = version
	resp["settings_snapshot"] = snapshot
}

// AuthMiddleware, when set by the main application, will be used to wrap
// tenancy handlers so they can enforce authentication/authorization.
// Set to nil to leave routes unprotected (not recommended).
var AuthMiddleware func(http.HandlerFunc) http.HandlerFunc

// installMap stores transient install scripts keyed by a short code.
type installEntry struct {
	Script    string
	Filename  string
	ExpiresAt time.Time
	OneTime   bool
}

type tenantPayload struct {
	ID           string `json:"id,omitempty"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	ContactName  string `json:"contact_name,omitempty"`
	ContactEmail string `json:"contact_email,omitempty"`
	ContactPhone string `json:"contact_phone,omitempty"`
	BusinessUnit string `json:"business_unit,omitempty"`
	BillingCode  string `json:"billing_code,omitempty"`
	Address      string `json:"address,omitempty"`
	LoginDomain  string `json:"login_domain,omitempty"`
}

type packageRequest struct {
	TenantID      string `json:"tenant_id"`
	Platform      string `json:"platform"`
	InstallerType string `json:"installer_type"`
	TTLMinutes    int    `json:"ttl_minutes"`
	Format        string `json:"format"`
	Component     string `json:"component"`
	Version       string `json:"version"`
	Arch          string `json:"arch"`
}

var installStore = struct {
	mu sync.Mutex
	m  map[string]installEntry
}{
	m: make(map[string]installEntry),
}

const maxInstallEntries = 4096

func storeInstallEntry(code string, entry installEntry) bool {
	installStore.mu.Lock()
	defer installStore.mu.Unlock()
	now := time.Now().UTC()
	for existing, value := range installStore.m {
		if !now.Before(value.ExpiresAt) {
			delete(installStore.m, existing)
		}
	}
	if _, exists := installStore.m[code]; !exists && len(installStore.m) >= maxInstallEntries {
		return false
	}
	installStore.m[code] = entry
	return true
}

var installCleanerOnce sync.Once

// serverVersion holds the running server semantic version. Main should set
// this via SetServerVersion so the download redirect can choose the matching
// agent release asset on GitHub.
var serverVersion string

// SetServerVersion sets the server version (called from main at startup).
func SetServerVersion(v string) {
	serverVersion = v
}

func requireTenancyEnabled(w http.ResponseWriter, r *http.Request) bool {
	if tenancyEnabled {
		return true
	}
	http.NotFound(w, r)
	return false
}

// RegisterRoutes registers HTTP handlers for tenancy endpoints. If a
// non-nil storage.Store is provided, handlers will persist tenants and tokens
// in the server DB; otherwise the in-memory store is used.
func RegisterRoutes(s storage.Store) {
	// Allow RegisterRoutes to be called multiple times (tests may swap muxes).
	// If routes already registered, just update the dbStore reference and return
	// to avoid duplicate http.HandleFunc registration which panics.
	// Delegate to the mux-aware registration using the default mux
	RegisterRoutesOnMux(http.DefaultServeMux, s)
}

// RegisterRoutesOnMux registers tenancy routes on the provided ServeMux.
// This is useful for tests which create their own muxes to avoid global
// DefaultServeMux races. It will always register the routes on the given
// mux; callers are responsible for ensuring they don't register the same
// routes multiple times on the same mux.
func RegisterRoutesOnMux(mux *http.ServeMux, s storage.Store) {
	dbStore = s
	// Wrap handlers with AuthMiddleware when provided
	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		if AuthMiddleware != nil {
			return AuthMiddleware(h)
		}
		return h
	}

	mux.HandleFunc("/api/v1/tenants", wrap(handleTenants))
	mux.HandleFunc("/api/v1/tenants/", wrap(handleTenantRoute))
	mux.HandleFunc("/api/v1/join-token", wrap(handleCreateJoinToken))
	mux.HandleFunc("/api/v1/agents/register-with-token", handleRegisterWithToken) // registration must remain public
	mux.HandleFunc("/api/v1/join-tokens", wrap(handleListJoinTokens))             // GET (admin)
	mux.HandleFunc("/api/v1/join-token/revoke", wrap(handleRevokeJoinToken))      // POST {"id":"..."}
	// Pending agent registrations (expired token capture)
	mux.HandleFunc("/api/v1/pending-registrations", wrap(handlePendingRegistrations))     // GET (admin)
	mux.HandleFunc("/api/v1/pending-registrations/", wrap(handlePendingRegistrationByID)) // GET/POST/DELETE by ID
	// Package generation (bootstrap script) - admin only
	mux.HandleFunc("/api/v1/packages", wrap(handleGeneratePackage))
	mux.HandleFunc("/api/v1/packages/send-email", wrap(handleSendDeploymentEmail))
	// Public redirect to latest agent binary on GitHub releases. This chooses
	// the release based on the running server version (set by main via
	// SetServerVersion) and redirects to the appropriate asset for the
	// requested platform/arch.
	mux.HandleFunc("/api/v1/agents/download/latest", handleAgentDownloadLatest)
	// Hosted install scripts (transient codes)
	mux.HandleFunc("/install/", handleInstall)

	// Start background cleanup for transient installs (runs once)
	installCleanerOnce.Do(func() { go installCleanupLoop() })
}

// handleTenants supports GET (list) and POST (create)
func handleTenants(w http.ResponseWriter, r *http.Request) {
	logDebug("handleTenants called", "method", r.Method, "tenancyEnabled", tenancyEnabled)
	if !requireTenancyEnabled(w, r) {
		logDebug("handleTenants: tenancy not enabled, returning 404")
		return
	}
	switch r.Method {
	case http.MethodGet:
		logDebug("handleTenants: GET request, checking authorization")
		if !authorizeOrReject(w, r, authz.ActionTenantsRead, authz.ResourceRef{}) {
			logDebug("handleTenants: authorization rejected for TenantsRead")
			return
		}
		logDebug("handleTenants: authorized, checking dbStore", "dbStore", dbStore != nil)
		if dbStore != nil {
			logDebug("handleTenants: querying database for tenants")
			list, err := dbStore.ListTenants(r.Context())
			if err != nil {
				logError("handleTenants: failed to list tenants from database", "error", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"failed to list tenants"}`))
				return
			}
			logDebug("handleTenants: successfully listed tenants from database", "count", len(list))
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(list)
			return
		}
		logDebug("handleTenants: using in-memory store")
		list := store.ListTenants()
		logDebug("handleTenants: listed tenants from memory", "count", len(list))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		logDebug("handleTenants: POST request, checking authorization")
		if !authorizeOrReject(w, r, authz.ActionTenantsWrite, authz.ResourceRef{}) {
			logWarn("handleTenants: authorization rejected for TenantsWrite")
			return
		}
		var in tenantPayload
		if err := webutil.DecodeJSONBody(nil, r, &in, 1<<20); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid json"}`))
			return
		}
		if strings.TrimSpace(in.Name) == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"name required"}`))
			return
		}
		if dbStore != nil {
			tn := &storage.Tenant{
				ID:           in.ID,
				Name:         in.Name,
				Description:  in.Description,
				ContactName:  in.ContactName,
				ContactEmail: in.ContactEmail,
				ContactPhone: in.ContactPhone,
				BusinessUnit: in.BusinessUnit,
				BillingCode:  in.BillingCode,
				Address:      in.Address,
				LoginDomain:  storage.NormalizeTenantDomain(in.LoginDomain),
			}
			if tn.ID == "" {
				// Let storage layer generate ID via SQL default
			}
			if err := dbStore.CreateTenant(r.Context(), tn); err != nil {
				logError("handleTenants: failed to create tenant in database", "error", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"failed to create tenant"}`))
				return
			}
			logInfo("handleTenants: tenant created successfully", "id", tn.ID, "name", tn.Name)

			// Invoke tenant created callback (e.g., to create INIT_SECRET join token)
			if tenantCreatedCallback != nil {
				tenantCreatedCallback(r.Context(), tn.ID)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tn)
			recordAudit(r, &storage.AuditEntry{
				Action:     "tenant.create",
				TargetType: "tenant",
				TargetID:   tn.ID,
				TenantID:   tn.ID,
				Details:    fmt.Sprintf("Created tenant %s", tn.Name),
				Metadata:   tenantAuditMetadata(tn.Name, tn.Description, tn.ContactName, tn.ContactEmail, tn.ContactPhone, tn.BusinessUnit, tn.BillingCode, tn.Address, tn.LoginDomain),
			})
			return
		}
		t, err := store.CreateTenant(Tenant{
			ID:           in.ID,
			Name:         in.Name,
			Description:  in.Description,
			ContactName:  in.ContactName,
			ContactEmail: in.ContactEmail,
			ContactPhone: in.ContactPhone,
			BusinessUnit: in.BusinessUnit,
			BillingCode:  in.BillingCode,
			Address:      in.Address,
			LoginDomain:  storage.NormalizeTenantDomain(in.LoginDomain),
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"failed to create tenant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(t)
		recordAudit(r, &storage.AuditEntry{
			Action:     "tenant.create",
			TargetType: "tenant",
			TargetID:   t.ID,
			TenantID:   t.ID,
			Details:    fmt.Sprintf("Created tenant %s", t.Name),
			Metadata:   tenantAuditMetadata(t.Name, t.Description, t.ContactName, t.ContactEmail, t.ContactPhone, t.BusinessUnit, t.BillingCode, t.Address, t.LoginDomain),
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleTenantRoute dispatches /api/v1/tenants/{id} and nested subresources like /settings.
func handleTenantRoute(w http.ResponseWriter, r *http.Request) {
	if !requireTenancyEnabled(w, r) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/tenants/")
	rest = strings.Trim(rest, "/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.SplitN(rest, "/", 2)
	tenantID := strings.TrimSpace(parts[0])
	if tenantID == "" {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 1 {
		handleTenantByID(w, r)
		return
	}
	subPath := strings.Trim(parts[1], "/")
	if subPath == "" {
		handleTenantByID(w, r)
		return
	}
	subParts := strings.SplitN(subPath, "/", 2)
	resource := subParts[0]
	remainder := ""
	if len(subParts) == 2 {
		remainder = subParts[1]
	}
	if handler := getTenantSubresourceHandler(resource); handler != nil {
		handler(w, r, tenantID, remainder)
		return
	}
	http.NotFound(w, r)
}

func handleTenantByID(w http.ResponseWriter, r *http.Request) {
	if !requireTenancyEnabled(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/tenants/")
	id = strings.Trim(id, "/")
	// Remove any subpath if present
	if idx := strings.Index(id, "/"); idx > 0 {
		id = id[:idx]
	}
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"tenant id required"}`))
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Allow tenant-scoped users to read their own tenant details
		if !authorizeOrReject(w, r, authz.ActionTenantsRead, authz.ResourceRef{TenantIDs: []string{id}}) {
			return
		}
		if dbStore != nil {
			tn, err := dbStore.GetTenant(r.Context(), id)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error":"tenant not found"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tn)
			return
		}
		existing, ok := store.tenants[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"tenant not found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(existing)
		return

	case http.MethodPut:
		if !authorizeOrReject(w, r, authz.ActionTenantsWrite, authz.ResourceRef{TenantIDs: []string{id}}) {
			return
		}
		var in tenantPayload
		if err := webutil.DecodeJSONBody(nil, r, &in, 1<<20); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid json"}`))
			return
		}
		if strings.TrimSpace(in.Name) == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"name required"}`))
			return
		}
		if dbStore != nil {
			tn, err := dbStore.GetTenant(r.Context(), id)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error":"tenant not found"}`))
				return
			}
			before := *tn
			tn.Name = in.Name
			tn.Description = in.Description
			tn.ContactName = in.ContactName
			tn.ContactEmail = in.ContactEmail
			tn.ContactPhone = in.ContactPhone
			tn.BusinessUnit = in.BusinessUnit
			tn.BillingCode = in.BillingCode
			tn.Address = in.Address
			tn.LoginDomain = storage.NormalizeTenantDomain(in.LoginDomain)
			if err := dbStore.UpdateTenant(r.Context(), tn); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"failed to update tenant"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tn)
			recordAudit(r, &storage.AuditEntry{
				Action:     "tenant.update",
				TargetType: "tenant",
				TargetID:   tn.ID,
				TenantID:   tn.ID,
				Details:    fmt.Sprintf("Updated tenant %s", tn.Name),
				Metadata: map[string]interface{}{
					"before": tenantAuditMetadata(before.Name, before.Description, before.ContactName, before.ContactEmail, before.ContactPhone, before.BusinessUnit, before.BillingCode, before.Address, before.LoginDomain),
					"after":  tenantAuditMetadata(tn.Name, tn.Description, tn.ContactName, tn.ContactEmail, tn.ContactPhone, tn.BusinessUnit, tn.BillingCode, tn.Address, tn.LoginDomain),
				},
			})
			return
		}
		existing, ok := store.tenants[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"tenant not found"}`))
			return
		}
		updated := Tenant{
			ID:           existing.ID,
			Name:         in.Name,
			Description:  in.Description,
			ContactName:  in.ContactName,
			ContactEmail: in.ContactEmail,
			ContactPhone: in.ContactPhone,
			BusinessUnit: in.BusinessUnit,
			BillingCode:  in.BillingCode,
			Address:      in.Address,
			LoginDomain:  storage.NormalizeTenantDomain(in.LoginDomain),
			CreatedAt:    existing.CreatedAt,
		}
		res, err := store.UpdateTenant(updated)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"failed to update tenant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
		recordAudit(r, &storage.AuditEntry{
			Action:     "tenant.update",
			TargetType: "tenant",
			TargetID:   res.ID,
			TenantID:   res.ID,
			Details:    fmt.Sprintf("Updated tenant %s", res.Name),
			Metadata: map[string]interface{}{
				"before": tenantAuditMetadata(existing.Name, existing.Description, existing.ContactName, existing.ContactEmail, existing.ContactPhone, existing.BusinessUnit, existing.BillingCode, existing.Address, existing.LoginDomain),
				"after":  tenantAuditMetadata(res.Name, res.Description, res.ContactName, res.ContactEmail, res.ContactPhone, res.BusinessUnit, res.BillingCode, res.Address, res.LoginDomain),
			},
		})

	case http.MethodDelete:
		if !authorizeOrReject(w, r, authz.ActionTenantsWrite, authz.ResourceRef{TenantIDs: []string{id}}) {
			return
		}
		if dbStore == nil {
			w.WriteHeader(http.StatusNotImplemented)
			w.Write([]byte(`{"error":"tenant deletion requires database storage"}`))
			return
		}
		// Check for assigned agents (safety check)
		agentCount, err := dbStore.CountTenantAgents(r.Context(), id)
		if err != nil {
			logError("failed to count tenant agents", "tenant_id", id, "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"failed to check tenant dependencies"}`))
			return
		}
		// Check for force parameter to allow deletion even with agents
		forceDelete := r.URL.Query().Get("force") == "true"
		if agentCount > 0 && !forceDelete {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":       "tenant has assigned agents",
				"agent_count": agentCount,
				"hint":        "Reassign or delete agents first, or use ?force=true to orphan them",
			})
			return
		}
		// Get tenant info for audit before deletion
		tn, err := dbStore.GetTenant(r.Context(), id)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"tenant not found"}`))
			return
		}
		tenantName := tn.Name
		// Perform deletion
		if err := dbStore.DeleteTenant(r.Context(), id); err != nil {
			logError("failed to delete tenant", "tenant_id", id, "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"failed to delete tenant"}`))
			return
		}
		logInfo("tenant deleted", "id", id, "name", tenantName, "orphaned_agents", agentCount)
		w.WriteHeader(http.StatusNoContent)
		recordAudit(r, &storage.AuditEntry{
			Action:     "tenant.delete",
			TargetType: "tenant",
			TargetID:   id,
			TenantID:   id,
			Details:    fmt.Sprintf("Deleted tenant %s", tenantName),
			Metadata: map[string]interface{}{
				"name":            tenantName,
				"orphaned_agents": agentCount,
				"force":           forceDelete,
			},
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleCreateJoinToken issues a join token. Body: {"tenant_id":"...","ttl_minutes":60,"one_time":false}
func handleCreateJoinToken(w http.ResponseWriter, r *http.Request) {
	if !requireTenancyEnabled(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		TenantID   string `json:"tenant_id"`
		TTLMinutes int    `json:"ttl_minutes"`
		OneTime    bool   `json:"one_time"`
	}
	if err := webutil.DecodeJSONBody(nil, r, &in, 1<<20); err != nil {
		pkgLogger.Warn("create-join-token: invalid JSON", "remote_addr", r.RemoteAddr, "error", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid json"}`))
		return
	}
	if pkgLogger != nil {
		pkgLogger.Info("create-join-token: request received", "tenant_id", in.TenantID, "ttl_minutes", in.TTLMinutes, "one_time", in.OneTime, "remote_addr", r.RemoteAddr)
	}
	if in.TTLMinutes <= 0 {
		in.TTLMinutes = 60
	}
	resource := authz.ResourceRef{}
	if strings.TrimSpace(in.TenantID) != "" {
		resource.TenantIDs = []string{strings.TrimSpace(in.TenantID)}
	}
	if !authorizeOrReject(w, r, authz.ActionJoinTokensWrite, resource) {
		return
	}
	if dbStore != nil {
		jt, raw, err := dbStore.CreateJoinToken(r.Context(), in.TenantID, in.TTLMinutes, in.OneTime)
		if err != nil {
			// Map storage errors to HTTP codes
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"failed to create token"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      raw,
			"tenant_id":  jt.TenantID,
			"expires_at": jt.ExpiresAt.Format(time.RFC3339),
		})
		recordAudit(r, &storage.AuditEntry{
			Action:     "join_token.create",
			TargetType: "join_token",
			TargetID:   jt.ID,
			TenantID:   jt.TenantID,
			Details:    fmt.Sprintf("Join token created for tenant %s", jt.TenantID),
			Metadata: map[string]interface{}{
				"ttl_minutes": in.TTLMinutes,
				"one_time":    in.OneTime,
				"expires_at":  jt.ExpiresAt.Format(time.RFC3339),
			},
		})
		return
	}
	jt, err := store.CreateJoinToken(in.TenantID, in.TTLMinutes, in.OneTime)
	if err != nil {
		if err == ErrTenantNotFound {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"tenant not found"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"failed to create token"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      jt.Token,
		"tenant_id":  jt.TenantID,
		"expires_at": jt.ExpiresAt.Format(time.RFC3339),
	})
	recordAudit(r, &storage.AuditEntry{
		Action:     "join_token.create",
		TargetType: "join_token",
		TargetID:   maskTokenValue(jt.Token),
		TenantID:   jt.TenantID,
		Details:    fmt.Sprintf("Join token created for tenant %s", jt.TenantID),
		Metadata: map[string]interface{}{
			"ttl_minutes": in.TTLMinutes,
			"one_time":    in.OneTime,
			"expires_at":  jt.ExpiresAt.Format(time.RFC3339),
		},
	})
}

// handleListJoinTokens returns a list of join tokens for a tenant. Query param: tenant_id
func handleListJoinTokens(w http.ResponseWriter, r *http.Request) {
	if !requireTenancyEnabled(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"tenant_id required"}`))
		return
	}
	if !authorizeOrReject(w, r, authz.ActionJoinTokensRead, authz.ResourceRef{TenantIDs: []string{tenantID}}) {
		return
	}
	if dbStore != nil {
		list, err := dbStore.ListJoinTokens(r.Context(), tenantID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"failed to list tokens"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
		return
	}
	// fallback: filter in-memory store
	all := make([]JoinToken, 0)
	for _, jt := range store.tokens {
		if jt.TenantID == tenantID {
			all = append(all, jt)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(all)
}

// handleRevokeJoinToken revokes a token by id. Body: {"id":"..."}
func handleRevokeJoinToken(w http.ResponseWriter, r *http.Request) {
	if !requireTenancyEnabled(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !authorizeOrReject(w, r, authz.ActionJoinTokensWrite, authz.ResourceRef{}) {
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := webutil.DecodeJSONBody(nil, r, &in, 1<<20); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid json"}`))
		return
	}
	if in.ID == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"id required"}`))
		return
	}
	if dbStore != nil {
		if err := dbStore.RevokeJoinToken(r.Context(), in.ID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"failed to revoke token"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		recordAudit(r, &storage.AuditEntry{
			Action:     "join_token.revoke",
			TargetType: "join_token",
			TargetID:   in.ID,
			Details:    "Join token revoked",
		})
		return
	}
	// fallback: remove from in-memory store
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.tokens[in.ID]; ok {
		delete(store.tokens, in.ID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		recordAudit(r, &storage.AuditEntry{
			Action:     "join_token.revoke",
			TargetType: "join_token",
			TargetID:   maskTokenValue(in.ID),
			Details:    "Join token revoked",
		})
		return
	}
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"token not found"}`))
}

// handlePendingRegistrations handles GET for listing pending registrations
func handlePendingRegistrations(w http.ResponseWriter, r *http.Request) {
	if !requireTenancyEnabled(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !authorizeOrReject(w, r, authz.ActionAgentsRead, authz.ResourceRef{}) {
		return
	}
	user, allowedTenants, scopeOK := requestTenantAccess(r)
	admin := user != nil && storage.NormalizeRole(string(user.Role)) == storage.RoleAdmin
	if !admin && !scopeOK {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if dbStore == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"database not available"}`))
		return
	}

	// Optional status filter
	status := r.URL.Query().Get("status")

	list, err := dbStore.ListPendingAgentRegistrations(r.Context(), status)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"failed to list pending registrations"}`))
		return
	}
	if !admin {
		filtered := make([]*storage.PendingAgentRegistration, 0, len(list))
		for _, reg := range list {
			if reg != nil && pendingTenantAllowed(allowedTenants, false, reg.ExpiredTenantID) {
				filtered = append(filtered, reg)
			}
		}
		list = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// handlePendingRegistrationByID handles GET (single), POST (approve/reject), DELETE
func handlePendingRegistrationByID(w http.ResponseWriter, r *http.Request) {
	if !requireTenancyEnabled(w, r) {
		return
	}
	if dbStore == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"database not available"}`))
		return
	}

	// Extract ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/pending-registrations/")
	id, err := strconv.ParseInt(path, 10, 64)
	if err != nil || id <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid registration id"}`))
		return
	}

	switch r.Method {
	case http.MethodGet:
		reg, err := dbStore.GetPendingAgentRegistration(r.Context(), id)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"registration not found"}`))
			return
		}
		user, allowedTenants, scopeOK := requestTenantAccess(r)
		admin := user != nil && storage.NormalizeRole(string(user.Role)) == storage.RoleAdmin
		if !scopeOK && !admin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !pendingTenantAllowed(allowedTenants, admin, reg.ExpiredTenantID) || !authorizeOrReject(w, r, authz.ActionAgentsRead, authz.ResourceRef{TenantIDs: []string{reg.ExpiredTenantID}}) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reg)

	case http.MethodPost:
		// Approve or reject
		reg, err := dbStore.GetPendingAgentRegistration(r.Context(), id)
		if err != nil || reg == nil {
			http.Error(w, "registration not found", http.StatusNotFound)
			return
		}
		user, allowedTenants, scopeOK := requestTenantAccess(r)
		admin := user != nil && storage.NormalizeRole(string(user.Role)) == storage.RoleAdmin
		if !scopeOK && !admin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !pendingTenantAllowed(allowedTenants, admin, reg.ExpiredTenantID) || !authorizeOrReject(w, r, authz.ActionAgentsWrite, authz.ResourceRef{TenantIDs: []string{reg.ExpiredTenantID}}) {
			return
		}
		if reg.Status != storage.PendingStatusPending {
			http.Error(w, "registration already reviewed", http.StatusConflict)
			return
		}
		var in struct {
			Action   string `json:"action"`              // "approve" or "reject"
			TenantID string `json:"tenant_id,omitempty"` // For approve
			Notes    string `json:"notes,omitempty"`     // For reject
		}
		if err := webutil.DecodeJSONBody(nil, r, &in, 1<<20); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid json"}`))
			return
		}

		username := "system"
		if user != nil && strings.TrimSpace(user.Username) != "" {
			username = strings.TrimSpace(user.Username)
		}

		switch in.Action {
		case "approve":
			if in.TenantID == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"tenant_id required for approval"}`))
				return
			}
			if !pendingTenantAllowed(allowedTenants, admin, in.TenantID) {
				http.Error(w, "tenant not permitted", http.StatusForbidden)
				return
			}
			if tenant, tenantErr := dbStore.GetTenant(r.Context(), strings.TrimSpace(in.TenantID)); tenantErr != nil || tenant == nil {
				http.Error(w, "tenant not found", http.StatusBadRequest)
				return
			}
			// Get registration details before approving for SSE broadcast
			if err := dbStore.ApprovePendingRegistration(r.Context(), id, in.TenantID, username); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"failed to approve registration"}`))
				return
			}
			// Create a new join token for this agent to use
			jt, rawToken, err := dbStore.CreateJoinToken(r.Context(), in.TenantID, 60*24, true) // 24hr one-time token
			if err != nil {
				logWarn("handlePendingRegistrationByID: failed to create approval token", "error", err)
			}
			// Broadcast pending_registration_approved event to UI via SSE
			if agentEventSink != nil {
				eventData := map[string]interface{}{
					"id":        id,
					"tenant_id": in.TenantID,
					"status":    storage.PendingStatusApproved,
				}
				if reg != nil {
					eventData["agent_id"] = reg.AgentID
					eventData["name"] = reg.Name
					eventData["hostname"] = reg.Hostname
				}
				agentEventSink("pending_registration_approved", eventData)
			}
			recordAudit(r, &storage.AuditEntry{
				Action:     "pending_registration.approve",
				TargetType: "pending_registration",
				TargetID:   strconv.FormatInt(id, 10),
				Details:    fmt.Sprintf("Pending registration approved for tenant %s", in.TenantID),
			})
			resp := map[string]interface{}{"success": true}
			if jt != nil {
				resp["join_token"] = rawToken
				resp["token_expires"] = jt.ExpiresAt
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case "reject":
			// Get registration details before rejecting for SSE broadcast
			regForReject := reg
			if err := dbStore.RejectPendingRegistration(r.Context(), id, username, in.Notes); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"failed to reject registration"}`))
				return
			}
			// Broadcast pending_registration_rejected event to UI via SSE
			if agentEventSink != nil {
				eventData := map[string]interface{}{
					"id":     id,
					"status": storage.PendingStatusRejected,
				}
				if regForReject != nil {
					eventData["agent_id"] = regForReject.AgentID
					eventData["name"] = regForReject.Name
					eventData["hostname"] = regForReject.Hostname
				}
				agentEventSink("pending_registration_rejected", eventData)
			}
			recordAudit(r, &storage.AuditEntry{
				Action:     "pending_registration.reject",
				TargetType: "pending_registration",
				TargetID:   strconv.FormatInt(id, 10),
				Details:    "Pending registration rejected",
			})
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"success": true})

		default:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"action must be 'approve' or 'reject'"}`))
		}

	case http.MethodDelete:
		reg, err := dbStore.GetPendingAgentRegistration(r.Context(), id)
		if err != nil || reg == nil {
			http.Error(w, "registration not found", http.StatusNotFound)
			return
		}
		user, allowedTenants, scopeOK := requestTenantAccess(r)
		admin := user != nil && storage.NormalizeRole(string(user.Role)) == storage.RoleAdmin
		if !scopeOK && !admin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !pendingTenantAllowed(allowedTenants, admin, reg.ExpiredTenantID) || !authorizeOrReject(w, r, authz.ActionAgentsWrite, authz.ResourceRef{TenantIDs: []string{reg.ExpiredTenantID}}) {
			return
		}
		if err := dbStore.DeletePendingAgentRegistration(r.Context(), id); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"failed to delete registration"}`))
			return
		}
		// Broadcast pending_registration_deleted event to UI via SSE
		if agentEventSink != nil {
			agentEventSink("pending_registration_deleted", map[string]interface{}{
				"id": id,
			})
		}
		recordAudit(r, &storage.AuditEntry{
			Action:     "pending_registration.delete",
			TargetType: "pending_registration",
			TargetID:   strconv.FormatInt(id, 10),
			Details:    "Pending registration deleted",
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleRegisterWithToken accepts {"token":"...","agent_id":"..."}
// Validates token and returns a placeholder agent token and tenant assignment.
func handleRegisterWithToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !agentBearerEnrollmentEnabled {
		http.Error(w, "legacy bearer enrollment is disabled; use mTLS enrollment", http.StatusGone)
		return
	}
	if !allowPublicEnrollment(r) {
		http.Error(w, "enrollment rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	var in struct {
		Token           string `json:"token"`
		AgentID         string `json:"agent_id"`
		Name            string `json:"name,omitempty"`
		AgentVersion    string `json:"agent_version,omitempty"`
		ProtocolVersion string `json:"protocol_version,omitempty"`
		Hostname        string `json:"hostname,omitempty"`
		IP              string `json:"ip,omitempty"`
		Platform        string `json:"platform,omitempty"`
		OSVersion       string `json:"os_version,omitempty"`
		GoVersion       string `json:"go_version,omitempty"`
		Architecture    string `json:"architecture,omitempty"`
		NumCPU          int    `json:"num_cpu,omitempty"`
		TotalMemoryMB   int64  `json:"total_memory_mb,omitempty"`
		BuildType       string `json:"build_type,omitempty"`
		GitCommit       string `json:"git_commit,omitempty"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := decoder.Decode(&in); err != nil {
		if pkgLogger != nil {
			pkgLogger.Warn("register-with-token: invalid JSON", "remote_addr", r.RemoteAddr, "error", err)
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid json"}`))
		return
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		http.Error(w, "expected one bounded JSON document", http.StatusBadRequest)
		return
	}
	if pkgLogger != nil {
		pkgLogger.Info("register-with-token: request received", "agent_id", in.AgentID, "name", in.Name, "hostname", in.Hostname, "platform", in.Platform, "version", in.AgentVersion, "token_length", len(in.Token), "remote_addr", r.RemoteAddr)
	}
	if in.Token == "" || in.AgentID == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"token and agent_id required"}`))
		return
	}
	if dbStore != nil {
		select {
		case publicEnrollmentSlots <- struct{}{}:
			defer func() { <-publicEnrollmentSlots }()
		case <-r.Context().Done():
			http.Error(w, "request canceled", http.StatusRequestTimeout)
			return
		}
		if pkgLogger != nil {
			pkgLogger.Debug("register-with-token: validating with dbStore", "agent_id", in.AgentID)
		}
		// Create or update agent in server DB with tenant assignment and issue a secure token
		// Generate secure random token (256 bits -> base64url)
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"failed to generate agent token"}`))
			return
		}
		token := base64.URLEncoding.EncodeToString(b)

		// Prepare agent metadata; persistence and token consumption commit together.
		ag := &storage.Agent{
			AgentID:         in.AgentID,
			Name:            in.Name,
			Hostname:        in.Hostname,
			IP:              in.IP,
			Platform:        in.Platform,
			Version:         in.AgentVersion,
			Token:           token,
			RegisteredAt:    time.Now().UTC(),
			LastSeen:        time.Now().UTC(),
			Status:          "active",
			OSVersion:       in.OSVersion,
			GoVersion:       in.GoVersion,
			Architecture:    in.Architecture,
			NumCPU:          in.NumCPU,
			TotalMemoryMB:   in.TotalMemoryMB,
			BuildType:       in.BuildType,
			GitCommit:       in.GitCommit,
			ProtocolVersion: in.ProtocolVersion,
			// Tenant assignment is supplied by the atomic enrollment transaction.
		}
		jt, err := dbStore.EnrollAgent(r.Context(), in.Token, ag)
		if err != nil {
			// Check if this is an expired (but known) token - we can capture these for admin review
			if storage.IsExpiredToken(err) {
				var tve *storage.TokenValidationError
				if errors.As(err, &tve) && tve.TenantID != "" {
					if pkgLogger != nil {
						pkgLogger.Info("register-with-token: capturing expired token registration",
							"agent_id", in.AgentID, "expired_tenant_id", tve.TenantID, "token_id", tve.TokenID)
					}
					// Create pending registration for admin review
					pending := &storage.PendingAgentRegistration{
						AgentID:         in.AgentID,
						Name:            in.Name,
						Hostname:        in.Hostname,
						IP:              r.RemoteAddr,
						Platform:        in.Platform,
						AgentVersion:    in.AgentVersion,
						ProtocolVersion: in.ProtocolVersion,
						ExpiredTokenID:  tve.TokenID,
						ExpiredTenantID: tve.TenantID,
						Status:          storage.PendingStatusPending,
					}
					// Do not create an unbounded stream of identical pending rows
					// when a stale agent retries. The endpoint is public and the
					// token hash lookup is deliberately expensive.
					pendingList, listErr := dbStore.ListPendingAgentRegistrations(r.Context(), storage.PendingStatusPending)
					if listErr == nil {
						duplicate := false
						for _, existing := range pendingList {
							if existing != nil && existing.AgentID == pending.AgentID && existing.ExpiredTokenID == pending.ExpiredTokenID {
								duplicate = true
								break
							}
						}
						if duplicate {
							w.WriteHeader(http.StatusUnauthorized)
							w.Write([]byte(`{"error":"token expired - registration pending admin approval"}`))
							return
						}
					}
					pendingID, createErr := dbStore.CreatePendingAgentRegistration(r.Context(), pending)
					if createErr != nil {
						if pkgLogger != nil {
							pkgLogger.Warn("register-with-token: failed to create pending registration", "error", createErr)
						}
					} else {
						// Broadcast pending_registration_created event to UI via SSE
						if agentEventSink != nil {
							agentEventSink("pending_registration_created", map[string]interface{}{
								"id":             pendingID,
								"agent_id":       in.AgentID,
								"name":           in.Name,
								"hostname":       in.Hostname,
								"platform":       in.Platform,
								"agent_version":  in.AgentVersion,
								"expired_tenant": tve.TenantID,
								"status":         storage.PendingStatusPending,
							})
						}
					}
					recordAudit(r, &storage.AuditEntry{
						ActorType: storage.AuditActorAgent,
						ActorID:   strings.TrimSpace(in.AgentID),
						ActorName: strings.TrimSpace(in.Name),
						Action:    "agent.register.pending",
						Severity:  storage.AuditSeverityInfo,
						Details:   "Agent registration captured: expired token - pending admin review",
						Metadata: map[string]interface{}{
							"token_prefix":      maskTokenValue(in.Token),
							"hostname":          strings.TrimSpace(in.Hostname),
							"platform":          strings.TrimSpace(in.Platform),
							"expired_tenant_id": tve.TenantID,
						},
					})
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{"error":"token expired - registration pending admin approval"}`))
					return
				}
			}

			// Unknown or invalid token - don't capture, just reject
			if pkgLogger != nil {
				pkgLogger.Warn("register-with-token: token validation failed", "agent_id", in.AgentID, "error", err, "remote_addr", r.RemoteAddr)
			}
			recordAudit(r, &storage.AuditEntry{
				ActorType: storage.AuditActorAgent,
				ActorID:   strings.TrimSpace(in.AgentID),
				ActorName: strings.TrimSpace(in.Name),
				Action:    "agent.register.token",
				Severity:  storage.AuditSeverityWarn,
				Details:   "Agent registration denied: invalid or unknown token",
				Metadata: map[string]interface{}{
					"token_prefix": maskTokenValue(in.Token),
					"hostname":     strings.TrimSpace(in.Hostname),
					"platform":     strings.TrimSpace(in.Platform),
				},
			})
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid or expired token"}`))
			return
		}

		if pkgLogger != nil {
			pkgLogger.Info("register-with-token: token validated successfully", "agent_id", in.AgentID, "tenant_id", jt.TenantID, "token_id", jt.ID)
		}

		if pkgLogger != nil {
			pkgLogger.Info("register-with-token: agent registered successfully", "agent_id", ag.AgentID, "tenant_id", ag.TenantID, "name", ag.Name)
		}

		emitAgentEvent("agent_registered", ag)

		resp := map[string]interface{}{
			"success":     true,
			"tenant_id":   jt.TenantID,
			"agent_token": token,
		}
		// Include tenant name for display purposes
		if tenant, err := dbStore.GetTenant(r.Context(), jt.TenantID); err == nil && tenant != nil {
			resp["tenant_name"] = tenant.Name
		}
		attachAgentSettings(resp, r.Context(), jt.TenantID, in.AgentID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		recordAudit(r, &storage.AuditEntry{
			ActorType: storage.AuditActorAgent,
			ActorID:   in.AgentID,
			ActorName: in.Name,
			TenantID:  jt.TenantID,
			Action:    "agent.register.token",
			Details:   "Agent registered via join token",
			Metadata: map[string]interface{}{
				"tenant_id":        jt.TenantID,
				"protocol_version": strings.TrimSpace(in.ProtocolVersion),
				"platform":         strings.TrimSpace(in.Platform),
				"hostname":         strings.TrimSpace(in.Hostname),
				"agent_version":    strings.TrimSpace(in.AgentVersion),
			},
		})
		return
	}

	jt, err := store.ValidateToken(in.Token)
	if err != nil {
		if err == ErrTokenNotFound || err == ErrTokenExpired {
			recordAudit(r, &storage.AuditEntry{
				ActorType: storage.AuditActorAgent,
				ActorID:   strings.TrimSpace(in.AgentID),
				ActorName: strings.TrimSpace(in.Name),
				Action:    "agent.register.token",
				Severity:  storage.AuditSeverityWarn,
				Details:   "Agent registration denied: invalid or expired join token",
				Metadata: map[string]interface{}{
					"token_prefix": maskTokenValue(in.Token),
					"hostname":     strings.TrimSpace(in.Hostname),
					"platform":     strings.TrimSpace(in.Platform),
				},
			})
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid or expired token"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"token validation failed"}`))
		return
	}

	// For non-DB (in-memory) fallback, generate a secure token and return it
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"failed to generate agent token"}`))
		return
	}
	placeholder := base64.URLEncoding.EncodeToString(b)
	now := time.Now().UTC()
	emitAgentEvent("agent_registered", &storage.Agent{
		AgentID:         in.AgentID,
		Name:            in.Name,
		Hostname:        in.Hostname,
		IP:              in.IP,
		Platform:        in.Platform,
		Version:         in.AgentVersion,
		ProtocolVersion: in.ProtocolVersion,
		Status:          "active",
		RegisteredAt:    now,
		LastSeen:        now,
		OSVersion:       in.OSVersion,
		GoVersion:       in.GoVersion,
		Architecture:    in.Architecture,
		NumCPU:          in.NumCPU,
		TotalMemoryMB:   in.TotalMemoryMB,
		BuildType:       in.BuildType,
		GitCommit:       in.GitCommit,
		TenantID:        jt.TenantID,
	})
	resp := map[string]interface{}{
		"success":     true,
		"tenant_id":   jt.TenantID,
		"agent_token": placeholder,
	}
	// Include tenant name for display purposes (may not exist in non-DB mode)
	if dbStore != nil {
		if tenant, err := dbStore.GetTenant(r.Context(), jt.TenantID); err == nil && tenant != nil {
			resp["tenant_name"] = tenant.Name
		}
	}
	attachAgentSettings(resp, r.Context(), jt.TenantID, in.AgentID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	recordAudit(r, &storage.AuditEntry{
		ActorType: storage.AuditActorAgent,
		ActorID:   in.AgentID,
		ActorName: in.Name,
		TenantID:  jt.TenantID,
		Action:    "agent.register.token",
		Details:   "Agent registered via join token",
		Metadata: map[string]interface{}{
			"tenant_id":        jt.TenantID,
			"protocol_version": strings.TrimSpace(in.ProtocolVersion),
			"platform":         strings.TrimSpace(in.Platform),
			"hostname":         strings.TrimSpace(in.Hostname),
			"agent_version":    strings.TrimSpace(in.AgentVersion),
		},
	})
}

func emitAgentEvent(eventType string, agent *storage.Agent) {
	if agentEventSink == nil || agent == nil {
		return
	}
	registeredAt := agent.RegisteredAt
	if registeredAt.IsZero() {
		registeredAt = time.Now().UTC()
	}
	lastSeen := agent.LastSeen
	if lastSeen.IsZero() {
		lastSeen = registeredAt
	}
	payload := map[string]interface{}{
		"agent_id":         agent.AgentID,
		"name":             agent.Name,
		"hostname":         agent.Hostname,
		"ip":               agent.IP,
		"platform":         agent.Platform,
		"version":          agent.Version,
		"protocol_version": agent.ProtocolVersion,
		"status":           agent.Status,
		"registered_at":    registeredAt,
		"last_seen":        lastSeen,
		"connection_type":  "none",
	}
	if agent.TenantID != "" {
		payload["tenant_id"] = agent.TenantID
	}
	if agent.OSVersion != "" {
		payload["os_version"] = agent.OSVersion
	}
	if agent.Architecture != "" {
		payload["architecture"] = agent.Architecture
	}
	if agent.BuildType != "" {
		payload["build_type"] = agent.BuildType
	}
	if agent.GitCommit != "" {
		payload["git_commit"] = agent.GitCommit
	}
	if agent.GoVersion != "" {
		payload["go_version"] = agent.GoVersion
	}
	if agent.NumCPU > 0 {
		payload["num_cpu"] = agent.NumCPU
	}
	if agent.TotalMemoryMB > 0 {
		payload["total_memory_mb"] = agent.TotalMemoryMB
	}
	agentEventSink(eventType, payload)
}

// handleGeneratePackage creates a bootstrap package/script for an agent to
// download and register using a join token. Request (POST) JSON:
// {"tenant_id":"...","platform":"linux|windows|darwin","installer_type":"script|archive","ttl_minutes":10}
// Response: attachment (script) or JSON with download_url depending on request.
func handleGeneratePackage(w http.ResponseWriter, r *http.Request) {
	if !requireTenancyEnabled(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in packageRequest
	if err := webutil.DecodeJSONBody(nil, r, &in, 1<<20); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid json"}`))
		return
	}
	in.TenantID = strings.TrimSpace(in.TenantID)
	if in.TenantID == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"tenant_id required"}`))
		return
	}
	if in.TTLMinutes <= 0 {
		in.TTLMinutes = 10
	}
	if in.TTLMinutes > 24*60 {
		in.TTLMinutes = 24 * 60
	}
	platform := normalizePlatform(in.Platform)
	installerType := strings.ToLower(strings.TrimSpace(in.InstallerType))
	if installerType == "" {
		installerType = "script"
	}
	if !authorizeOrReject(w, r, authz.ActionPackagesGenerate, authz.ResourceRef{TenantIDs: []string{in.TenantID}}) {
		return
	}

	// Validate tenant exists
	if dbStore != nil {
		_, err := dbStore.GetTenant(r.Context(), in.TenantID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"tenant not found"}`))
			return
		}
	} else {
		store.mu.Lock()
		_, ok := store.tenants[in.TenantID]
		store.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"tenant not found"}`))
			return
		}
	}

	var rawToken string
	if dbStore != nil {
		_, rt, err := dbStore.CreateJoinToken(r.Context(), in.TenantID, in.TTLMinutes, true)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"failed to create token"}`))
			return
		}
		rawToken = rt
	} else {
		jt, err := store.CreateJoinToken(in.TenantID, in.TTLMinutes, true)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"failed to create token"}`))
			return
		}
		rawToken = jt.Token
	}

	serverURL := buildTenancyExternalURL(r)

	recordAudit(r, &storage.AuditEntry{
		Action:     "package.generate",
		TargetType: "install_package",
		TargetID:   in.TenantID,
		TenantID:   in.TenantID,
		Details:    "Bootstrap package generated",
		Metadata: map[string]interface{}{
			"platform":       platform,
			"installer_type": installerType,
			"format":         strings.ToLower(strings.TrimSpace(in.Format)),
			"ttl_minutes":    in.TTLMinutes,
		},
	})

	switch installerType {
	case "script":
		script, filename := buildBootstrapScript(platform, serverURL, rawToken)
		if script == "" || filename == "" {
			writeJSONError(w, http.StatusInternalServerError, "unable to build bootstrap script")
			return
		}
		code, err := randomHex(12)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to generate install code")
			return
		}
		oneTimeDownload := true
		if inOneTime, ok := r.URL.Query()["one_time_download"]; ok && len(inOneTime) > 0 {
			value := strings.ToLower(strings.TrimSpace(inOneTime[0]))
			if value == "false" || value == "0" {
				oneTimeDownload = false
			}
		}
		expiresAt := time.Now().UTC().Add(time.Duration(in.TTLMinutes) * time.Minute)
		if !storeInstallEntry(code, installEntry{Script: script, Filename: filename, ExpiresAt: expiresAt, OneTime: oneTimeDownload}) {
			writeJSONError(w, http.StatusServiceUnavailable, "too many active install packages")
			return
		}

		downloadURL := fmt.Sprintf("%s/install/%s", serverURL, code)
		w.Header().Set("Content-Type", "application/json")
		oneLiner := fmt.Sprintf("curl -fsSL '%s' | sudo sh", escapePOSIXSingleQuoted(downloadURL))
		if platform == "windows" {
			oneLiner = fmt.Sprintf("irm '%s' | iex", escapePowerShellSingleQuoted(downloadURL))
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"script":       script,
			"filename":     filename,
			"download_url": downloadURL,
			"one_liner":    oneLiner,
		})
		return
	default:
		writeJSONError(w, http.StatusBadRequest, "unsupported installer_type (only 'script' is supported)")
		return
	}
}

// handleSendDeploymentEmail generates a bootstrap script and sends it via email.
// Request (POST) JSON:
// {"tenant_id":"...","platform":"linux|windows|darwin","email":"user@example.com","ttl_minutes":60}
func handleSendDeploymentEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireTenancyEnabled(w, r) {
		return
	}
	// Check email sender is configured
	if emailSender == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "email sending not configured (SMTP not enabled)")
		return
	}

	var in struct {
		TenantID   string `json:"tenant_id"`
		Platform   string `json:"platform"`
		Email      string `json:"email"`
		TTLMinutes int    `json:"ttl_minutes"`
	}
	if err := webutil.DecodeJSONBody(nil, r, &in, 1<<20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if in.TenantID == "" {
		writeJSONError(w, http.StatusBadRequest, "tenant_id required")
		return
	}
	if in.Email == "" {
		writeJSONError(w, http.StatusBadRequest, "email address required")
		return
	}
	if in.TTLMinutes <= 0 {
		in.TTLMinutes = 60
	}
	if in.TTLMinutes > 24*60 {
		in.TTLMinutes = 24 * 60
	}

	platform := normalizePlatform(in.Platform)
	if platform == "" {
		platform = "linux"
	}

	// Authorize the request (same permission as package generation)
	if !authorizeOrReject(w, r, authz.ActionPackagesGenerate, authz.ResourceRef{TenantIDs: []string{in.TenantID}}) {
		return
	}

	// Fetch tenant info for email context
	ctx := r.Context()
	tenantName := ""
	if dbStore != nil {
		tenant, err := dbStore.GetTenant(ctx, in.TenantID)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "tenant not found")
			return
		}
		tenantName = tenant.Name
	} else {
		store.mu.Lock()
		t, ok := store.tenants[in.TenantID]
		store.mu.Unlock()
		if !ok {
			writeJSONError(w, http.StatusNotFound, "tenant not found")
			return
		}
		tenantName = t.Name
	}

	// Determine server URL (respects X-Forwarded-Proto for proxy scenarios)
	serverURL := buildTenancyExternalURL(r)

	// Create a join token
	var rawToken string
	if dbStore != nil {
		_, rt, err := dbStore.CreateJoinToken(ctx, in.TenantID, in.TTLMinutes, true)
		if err != nil {
			logError("failed to create join token for email send", "error", err, "tenant_id", in.TenantID)
			writeJSONError(w, http.StatusInternalServerError, "failed to create join token: "+err.Error())
			return
		}
		rawToken = rt
	} else {
		jt, err := store.CreateJoinToken(in.TenantID, in.TTLMinutes, true)
		if err != nil {
			logError("failed to create join token for email send", "error", err, "tenant_id", in.TenantID)
			writeJSONError(w, http.StatusInternalServerError, "failed to create join token: "+err.Error())
			return
		}
		rawToken = jt.Token
	}

	// Build the bootstrap script
	script, filename := buildBootstrapScript(platform, serverURL, rawToken)
	if script == "" {
		writeJSONError(w, http.StatusInternalServerError, "failed to generate bootstrap script")
		return
	}

	// Store for download URL (not one-time since email may be opened multiple times)
	code, err := randomHex(12)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to generate install code")
		return
	}
	expiresAt := time.Now().UTC().Add(time.Duration(in.TTLMinutes) * time.Minute)
	if !storeInstallEntry(code, installEntry{Script: script, Filename: filename, ExpiresAt: expiresAt, OneTime: false}) {
		writeJSONError(w, http.StatusServiceUnavailable, "too many active install packages")
		return
	}

	downloadURL := fmt.Sprintf("%s/install/%s", serverURL, code)
	oneLiner := fmt.Sprintf("curl -fsSL '%s' | sudo sh", escapePOSIXSingleQuoted(downloadURL))
	if platform == "windows" {
		oneLiner = fmt.Sprintf("irm '%s' | iex", escapePowerShellSingleQuoted(downloadURL))
	}

	// Get the sender name from the request context (user who initiated)
	senderName := ""
	if getUserFromContext != nil {
		if user := getUserFromContext(r.Context()); user != nil {
			senderName = user.Username
		}
	}

	// Generate email content
	expiresIn := fmt.Sprintf("%d minutes", in.TTLMinutes)
	if in.TTLMinutes >= 60 {
		hours := in.TTLMinutes / 60
		mins := in.TTLMinutes % 60
		if mins == 0 {
			expiresIn = fmt.Sprintf("%d hour(s)", hours)
		} else {
			expiresIn = fmt.Sprintf("%d hour(s) %d minutes", hours, mins)
		}
	}

	// Get theme setting
	theme := "auto"
	if emailThemeGetter != nil {
		theme = emailThemeGetter()
	}

	// Generate the email HTML/text using the email package
	htmlBody, textBody, err := generateDeploymentEmail(theme, in.Email, platform, oneLiner, script, downloadURL, expiresIn, tenantName, serverURL, senderName)
	if err != nil {
		logError("failed to generate deployment email", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "failed to generate email: "+err.Error())
		return
	}

	// Send the email
	subject := "PrintMaster Agent Installation Instructions"
	if tenantName != "" {
		subject = fmt.Sprintf("PrintMaster Agent Installation - %s", tenantName)
	}
	if err := emailSender(in.Email, subject, htmlBody, textBody); err != nil {
		logError("failed to send deployment email", "error", err, "email", in.Email)
		writeJSONError(w, http.StatusInternalServerError, "failed to send email: "+err.Error())
		return
	}

	// Record audit
	recordAudit(r, &storage.AuditEntry{
		Action:     "deployment_email.send",
		TargetType: "agent_deployment",
		TargetID:   in.Email,
		TenantID:   in.TenantID,
		Details:    "Agent deployment instructions emailed",
		Metadata: map[string]interface{}{
			"tenant_id":   in.TenantID,
			"platform":    platform,
			"email":       in.Email,
			"ttl_minutes": in.TTLMinutes,
		},
	})

	logInfo("deployment email sent", "email", in.Email, "tenant_id", in.TenantID, "platform", platform)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Deployment instructions sent to %s", in.Email),
	})
}

// handleInstall serves hosted install scripts by short code. URL: /install/{code}/{filename}
func handleInstall(w http.ResponseWriter, r *http.Request) {
	// expect path /install/{code}/{filename}
	p := strings.TrimPrefix(r.URL.Path, "/install/")
	parts := strings.SplitN(p, "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	code := parts[0]

	installStore.mu.Lock()
	entry, ok := installStore.m[code]
	// If one-time, remove immediately (we'll serve below)
	if ok && entry.OneTime {
		delete(installStore.m, code)
	}
	installStore.mu.Unlock()
	if !ok || time.Now().UTC().After(entry.ExpiresAt) {
		http.NotFound(w, r)
		return
	}

	// Serve script with appropriate content-type based on filename
	contentType := "text/plain; charset=utf-8"
	if strings.HasSuffix(entry.Filename, ".sh") {
		contentType = "application/x-sh"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+entry.Filename+"\"")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_, _ = w.Write([]byte(entry.Script))
}

// installCleanupLoop periodically removes expired install entries.
func installCleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().UTC()
		installStore.mu.Lock()
		for k, v := range installStore.m {
			if now.After(v.ExpiresAt) {
				delete(installStore.m, k)
			}
		}
		installStore.mu.Unlock()
	}
}

func buildBootstrapScript(platform, serverURL, token string) (string, string) {
	// Bootstrap values are embedded into shell scripts.  Quote them for the
	// target shell before formatting the templates so a malicious Host header
	// or token can never become executable script text.
	serverURL = validateBootstrapURL(serverURL)
	switch normalizePlatform(platform) {
	case "windows":
		return fmt.Sprintf(windowsBootstrapScript, escapePowerShellSingleQuoted(serverURL), escapePowerShellSingleQuoted(token)), "install.ps1"
	default:
		return fmt.Sprintf(unixBootstrapScript, escapePOSIXSingleQuoted(serverURL), escapePOSIXSingleQuoted(token)), "install.sh"
	}
}

func escapePowerShellSingleQuoted(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func escapePOSIXSingleQuoted(value string) string {
	return strings.ReplaceAll(value, "'", "'\"'\"'")
}

func validateBootstrapURL(value string) string {
	value = strings.TrimSpace(value)
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		!strings.EqualFold(u.Scheme, "https") {
		// A generated installer must never silently downgrade to clear text.
		// Keep a syntactically valid placeholder so the script fails closed.
		return "https://invalid.invalid"
	}
	return value
}

const windowsBootstrapScript = `# PowerShell bootstrap for PrintMaster
$ErrorActionPreference = "Stop"
$server = '%s'
$token = '%s'

# ANSI color codes
$ESC = [char]27
$ColorReset   = "$ESC[0m"
$ColorRed     = "$ESC[31m"
$ColorGreen   = "$ESC[32m"
$ColorYellow  = "$ESC[33m"
$ColorCyan    = "$ESC[36m"
$ColorWhite   = "$ESC[37m"
$ColorBold    = "$ESC[1m"
$ColorDim     = "$ESC[2m"

# Enable virtual terminal processing for ANSI colors on Windows
$null = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try {
	$mode = 0
	$handle = [Console]::OutputHandle
	$null = [Console]::TreatControlCAsInput = $false
	# Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004)
	Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ConsoleHelper {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);
}
"@
	$stdout = [ConsoleHelper]::GetStdHandle(-11)
	$mode = 0
	$null = [ConsoleHelper]::GetConsoleMode($stdout, [ref]$mode)
	$null = [ConsoleHelper]::SetConsoleMode($stdout, $mode -bor 0x0004)
} catch {
	# ANSI might not work on older systems, but continue anyway
}

# Build ASCII art with backticks using char code to avoid escaping issues
$BT = [char]96
$asciiArt = @"

  $ColorCyan+----------------------------------------------------------------------------------+
  |                                                                                  |
  |   ____________ _____ _   _ ________  ___  ___   _____ _____ ___________          |
  |   | ___ \ ___ \_   _| \ | |_   _|  \/  | / _ \ /  ___|_   _|  ___| ___ \         |
  |   | |_/ / |_/ / | | |  \| | | | | .  . |/ /_\ \\ $BT--.  | | | |__ | |_/ /         |
  |   |  __/|    /  | | | . $BT | | | | |\/| ||  _  | $BT--. \ | | |  __||    /          |
  |   | |   | |\ \ _| |_| |\  | | | | |  | || | | |/\__/ / | | | |___| |\ \          |
  |   \_|   \_| \_|\___/\_| \_/ \_/ \_|  |_/\_| |_/\____/  \_/ \____/\_| \_|         |
  |                                                                                  |
  +----------------------------------------------------------------------------------+$ColorReset

"@

function Show-Banner {
	Clear-Host
	Write-Host $asciiArt
	$centerPad = "                         "
	Write-Host "$centerPad${ColorBold}Fleet Management Agent Installer${ColorReset}"
	Write-Host "$centerPad${ColorDim}Server: $server${ColorReset}"
	Write-Host ""
	Write-Host ""
}

# Track if we have an active progress line that needs to be cleared
$script:progressLineActive = $false

function Clear-ProgressLine {
	if ($script:progressLineActive) {
		# Clear current line and move to next line
		Write-Host ""
		$script:progressLineActive = $false
	}
}

function Show-Success {
	param([string]$Message)
	Clear-ProgressLine
	Write-Host "  ${ColorGreen}[OK]${ColorReset} $Message"
}

function Show-Error {
	param([string]$Message)
	Clear-ProgressLine
	Write-Host "  ${ColorRed}[X]${ColorReset} $Message"
}

function Show-Info {
	param([string]$Message)
	Clear-ProgressLine
	Write-Host "  ${ColorCyan}[*]${ColorReset} $Message"
}

function Show-Warning {
	param([string]$Message)
	Clear-ProgressLine
	Write-Host "  ${ColorYellow}[!]${ColorReset} $Message"
}

function Show-Progress {
	param([int]$Percent, [string]$Message)
	$barWidth = 40
	$filled = [math]::Floor(($Percent * $barWidth) / 100)
	$empty = $barWidth - $filled
	$bar = ("$ColorGreen" + ([string][char]9608 * $filled) + "$ColorDim" + ([string][char]9617 * $empty) + "$ColorReset")
	$pct = $Percent.ToString().PadLeft(3)
	# Use carriage return to overwrite line in place (works in PS5 and PS7)
	# Write without newline so we can overwrite on next call
	$line = "  $ColorCyan[$bar$ColorCyan]$ColorReset $pct%% $ColorWhite$Message$ColorReset"
	# Pad to clear any previous longer text
	$padWidth = 90
	$line = $line.PadRight($padWidth)
	$CR = [char]13
	Write-Host -NoNewline "$CR$line"
	$script:progressLineActive = $true
}

function Show-CompletionBox {
	param([bool]$Success, [string]$Message)
	Clear-ProgressLine
	Write-Host ""
	Write-Host ""
	if ($Success) {
		$color = $ColorGreen
		$icon = "[OK]"
	} else {
		$color = $ColorRed
		$icon = "[X]"
	}
	$boxWidth = 60
	$topBottom = "=" * ($boxWidth - 2)
	$emptyLine = " " * ($boxWidth - 2)
	$contentWidth = $boxWidth - 4
	$textWithIcon = "  $icon  $Message"
	$paddingNeeded = $contentWidth - $textWithIcon.Length
	$paddingLeft = [math]::Floor($paddingNeeded / 2)
	$paddingRight = $paddingNeeded - $paddingLeft
	$indent = "          "
	
	Write-Host "$indent$color+$topBottom+$ColorReset"
	Write-Host "$indent$color|$emptyLine|$ColorReset"
	Write-Host "$indent$color|$(" " * $paddingLeft)  $icon  ${ColorBold}$Message${ColorReset}$color$(" " * $paddingRight)|$ColorReset"
	Write-Host "$indent$color|$emptyLine|$ColorReset"
	Write-Host "$indent$color+$topBottom+$ColorReset"
	Write-Host ""
}

function Assert-Administrator {
	$current = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object Security.Principal.WindowsPrincipal($current)
	if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		Show-Error "This installer must be run from an elevated PowerShell session."
		Write-Host ""
		Write-Host "  ${ColorDim}Run PowerShell as Administrator and try again.${ColorReset}"
		exit 1
	}
}

function Set-TlsPolicy {
	param([string]$TlsVersion = "Modern")
	
	# Set TLS version
	switch ($TlsVersion) {
		"Tls13" {
			try {
				[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls13
			} catch {
				throw "TLS 1.3 not supported on this system"
			}
		}
		"Tls12" {
			[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
		}
		default {
			# Modern: TLS 1.3 + 1.2 combined
			[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
			try {
				[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 12288
			} catch { }
		}
	}
	
	# Always retain the platform certificate and hostname validation policy.
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
}

function Download-Secure {
	param([string]$Url, [string]$OutFile)
	if (-not $Url.StartsWith("https://", [System.StringComparison]::OrdinalIgnoreCase)) {
		throw "Refusing to download over a non-HTTPS URL. Configure server.external_url with HTTPS."
	}
	
	# Detect PowerShell version for optimal method selection
	$isPwsh7 = $PSVersionTable.PSVersion.Major -ge 6
	$psVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
	
	Show-Info "Detected PowerShell $psVersion"
	
	# Build a secure fallback chain. Every method uses normal certificate
	# validation; there is deliberately no HTTP or skip-certificate fallback.
	$secureAttempts = @()
	
	if ($isPwsh7) {
		# PowerShell 7+ has native TLS 1.3 and better cert handling
		$secureAttempts += @{ Name = "TLS 1.3 (PowerShell 7+)"; Method = "Pwsh7"; TlsVersion = "Tls13"; Url = $Url }
		$secureAttempts += @{ Name = "TLS 1.2 (PowerShell 7+)"; Method = "Pwsh7"; TlsVersion = "Tls12"; Url = $Url }
	}
	
	# WebClient methods (works on all PS versions)
	$secureAttempts += @{ Name = "TLS 1.3 (WebClient)"; Method = "WebClient"; TlsVersion = "Tls13"; Url = $Url }
	$secureAttempts += @{ Name = "TLS 1.2 (WebClient)"; Method = "WebClient"; TlsVersion = "Tls12"; Url = $Url }
	
	$lastError = $null
	$totalSecure = $secureAttempts.Count
	$attemptNum = 0
	
	# Try secure methods first (no user prompts needed)
	foreach ($attempt in $secureAttempts) {
		$attemptNum++
		try {
			Show-Info "Attempt $attemptNum of $totalSecure - $($attempt.Name)..."
			
			Set-TlsPolicy -TlsVersion $attempt.TlsVersion
			
			switch ($attempt.Method) {
				"Pwsh7" {
					Invoke-WebRequest -Uri $attempt.Url -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
				}
				"WebClient" {
					$wc = New-Object System.Net.WebClient
					$wc.DownloadFile($attempt.Url, $OutFile)
				}
			}
			
			Show-Success "Downloaded via $($attempt.Name)"
			return $true
		} catch {
			$lastError = $_.Exception.Message
			if (Test-Path $OutFile) {
				Remove-Item -Path $OutFile -Force -ErrorAction SilentlyContinue
			}
		}
	}
	
	# Secure methods failed. Stop rather than downgrade transport or certificate
	# validation, because the downloaded executable and enrollment token are
	# security-sensitive.
	Show-Warning "All secure download methods failed."
	Show-Warning "Last error: $lastError"
	Show-Error "Download failed. HTTPS certificate validation is required."
	return $false
}

function Remove-ExistingInstallation {
	$svc = Get-Service -Name "PrintMasterAgent" -ErrorAction SilentlyContinue
	if ($svc) {
		Show-Warning "Found existing installation. Removing..."
		
		if ($svc.Status -eq 'Running') {
			Show-Info "Stopping service..."
			Stop-Service -Name "PrintMasterAgent" -Force -ErrorAction SilentlyContinue
			Start-Sleep -Seconds 2
			Show-Success "Service stopped"
		}
		
		# Check for MSI-based installation first
		$uninstallKeys = @(
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
			"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
		)
		
		$productCode = $null
		foreach ($keyPath in $uninstallKeys) {
			$items = Get-ItemProperty $keyPath -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*PrintMaster*Agent*" }
			if ($items) {
				foreach ($item in $items) {
					if ($item.PSChildName -match '^\{[A-F0-9-]+\}$') {
						$productCode = $item.PSChildName
						break
					}
				}
			}
			if ($productCode) { break }
		}
		
		if ($productCode) {
			Show-Info "Uninstalling previous MSI version..."
			$uninstallProc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x",$productCode,"/qn","/norestart" -Wait -PassThru
			if ($uninstallProc.ExitCode -eq 0 -or $uninstallProc.ExitCode -eq 1605) {
				Show-Success "Previous MSI installation removed"
			} else {
				Show-Warning "MSI uninstall returned code $($uninstallProc.ExitCode). Continuing..."
			}
			Start-Sleep -Seconds 2
		} else {
			# No MSI found - try to uninstall service via exe or sc.exe
			$programData = ${env:ProgramData}
			if ([string]::IsNullOrWhiteSpace($programData)) { $programData = "C:\\ProgramData" }
			$existingExe = Join-Path $programData "PrintMaster\bin\printmaster-agent.exe"
			
			if (Test-Path $existingExe) {
				Show-Info "Uninstalling existing service..."
				$uninstallProc = Start-Process -FilePath $existingExe -ArgumentList "--service","uninstall","--silent" -Wait -PassThru -NoNewWindow
				if ($uninstallProc.ExitCode -eq 0) {
					Show-Success "Service uninstalled"
				} else {
					Show-Warning "Service uninstall returned code $($uninstallProc.ExitCode)"
				}
			} else {
				Show-Info "Removing service entry directly..."
				& sc.exe delete "PrintMasterAgent" 2>$null
				Show-Success "Service entry removed"
			}
			Start-Sleep -Seconds 1
		}
	}
	
	# Stop any running processes
	$procs = Get-Process -Name "printmaster-agent" -ErrorAction SilentlyContinue
	if ($procs) {
		Show-Info "Stopping running processes..."
		$procs | Stop-Process -Force -ErrorAction SilentlyContinue
		Start-Sleep -Seconds 1
		Show-Success "Processes stopped"
	}
	
	# Clean up old installation directories
	$programData = ${env:ProgramData}
	if ([string]::IsNullOrWhiteSpace($programData)) { $programData = "C:\\ProgramData" }
	$oldBinDir = Join-Path $programData "PrintMaster\bin"
	if (Test-Path $oldBinDir) {
		Show-Info "Removing old binaries..."
		Remove-Item -Path $oldBinDir -Recurse -Force -ErrorAction SilentlyContinue
		Show-Success "Old binaries removed"
	}
	
	# Also clean up Program Files location (from old MSI installs)
	$programFiles = ${env:ProgramFiles}
	if ([string]::IsNullOrWhiteSpace($programFiles)) { $programFiles = "C:\\Program Files" }
	$oldMsiDir = Join-Path $programFiles "PrintMaster"
	if (Test-Path $oldMsiDir) {
		Show-Info "Removing old MSI installation directory..."
		Remove-Item -Path $oldMsiDir -Recurse -Force -ErrorAction SilentlyContinue
		Show-Success "Old MSI directory removed"
	}
	
	# Clean up our own uninstall registry entry if present
	$uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PrintMasterAgent"
	if (Test-Path $uninstallKey) {
		Remove-Item -Path $uninstallKey -Force -ErrorAction SilentlyContinue
	}
}

# ========== MAIN INSTALLATION ==========

Show-Banner
Assert-Administrator

$programData = ${env:ProgramData}
if ([string]::IsNullOrWhiteSpace($programData)) {
	$programData = "C:\\ProgramData"
}

$dataRoot = Join-Path $programData "PrintMaster"
$configDir = Join-Path $dataRoot "agent"
$configPath = Join-Path $configDir "config.toml"
$installDir = Join-Path $programData "PrintMaster\bin"
$exePath = Join-Path $installDir "printmaster-agent.exe"
$tempDir = Join-Path $env:TEMP "PrintMaster-Install"
$tempExePath = Join-Path $tempDir "printmaster-agent.exe"

# Step 1: Remove existing installation
Show-Progress -Percent 5 -Message "Checking for existing installation..."
Start-Sleep -Milliseconds 300
Remove-ExistingInstallation

# Step 2: Prepare directories
Show-Progress -Percent 15 -Message "Preparing directories..."
Start-Sleep -Milliseconds 200
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
Show-Success "Directories ready"

# Step 3: Write configuration
Show-Progress -Percent 25 -Message "Writing configuration..."

$agentName = $env:COMPUTERNAME
if ([string]::IsNullOrWhiteSpace($agentName)) {
	$agentName = "windows-agent"
}

$configContent = @"
[server]
enabled = true
url = "$server"
name = "$agentName"
token = "$token"
insecure_skip_verify = false
"@
Set-Content -Path $configPath -Value $configContent -Encoding UTF8
Show-Success "Configuration saved to $configPath"

# Step 4: Download agent
Show-Progress -Percent 35 -Message "Downloading agent..."

$downloadUrl = "$server/api/v1/agents/download/latest?platform=windows&arch=amd64&format=exe&proxy=1"

if (-not (Download-Secure -Url $downloadUrl -OutFile $tempExePath)) {
	Show-CompletionBox -Success $false -Message "Download Failed"
	exit 1
}

if (-not (Test-Path $tempExePath)) {
	Show-Error "Agent executable missing after download."
	Show-CompletionBox -Success $false -Message "Download Failed"
	exit 1
}

try {
	Unblock-File -Path $tempExePath -ErrorAction SilentlyContinue
} catch { }

$fileSize = (Get-Item $tempExePath).Length / 1MB
Show-Success "Downloaded agent ($([math]::Round($fileSize, 1)) MB)"

# Step 5: Install agent
Show-Progress -Percent 50 -Message "Installing PrintMaster Agent..."

# Copy executable to install directory
Show-Info "Copying agent to install directory..."
Copy-Item -Path $tempExePath -Destination $exePath -Force
Show-Success "Agent installed to $installDir"

# Step 6: Install and start service
Show-Progress -Percent 70 -Message "Configuring Windows service..."
Show-Info "Installing service..."

$installProc = Start-Process -FilePath $exePath -ArgumentList "--service","install","--silent" -Wait -PassThru -NoNewWindow
if ($installProc.ExitCode -ne 0) {
	Show-Error "Service installation failed with exit code $($installProc.ExitCode)"
	Show-CompletionBox -Success $false -Message "Service Install Failed"
	exit $installProc.ExitCode
}
Show-Success "Service installed"

# Register in Add/Remove Programs
Show-Progress -Percent 78 -Message "Registering uninstaller..."
$uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PrintMasterAgent"
New-Item -Path $uninstallKey -Force | Out-Null

# Get version from the executable
$versionInfo = (Get-Item $exePath).VersionInfo
$displayVersion = if ($versionInfo.ProductVersion) { $versionInfo.ProductVersion } else { "1.0.0" }
$fileSize = [math]::Round((Get-Item $exePath).Length / 1KB)
$installDate = Get-Date -Format "yyyyMMdd"
$quotedExePath = '"' + $exePath + '"'

Set-ItemProperty -Path $uninstallKey -Name "DisplayName" -Value "PrintMaster Agent"
Set-ItemProperty -Path $uninstallKey -Name "DisplayVersion" -Value $displayVersion
Set-ItemProperty -Path $uninstallKey -Name "Publisher" -Value "PrintMaster"
Set-ItemProperty -Path $uninstallKey -Name "InstallLocation" -Value $installDir
Set-ItemProperty -Path $uninstallKey -Name "InstallDate" -Value $installDate
Set-ItemProperty -Path $uninstallKey -Name "UninstallString" -Value "$quotedExePath --service uninstall"
Set-ItemProperty -Path $uninstallKey -Name "QuietUninstallString" -Value "$quotedExePath --service uninstall --silent"
Set-ItemProperty -Path $uninstallKey -Name "EstimatedSize" -Value $fileSize -Type DWord
Set-ItemProperty -Path $uninstallKey -Name "NoModify" -Value 1 -Type DWord
Set-ItemProperty -Path $uninstallKey -Name "NoRepair" -Value 1 -Type DWord
Set-ItemProperty -Path $uninstallKey -Name "DisplayIcon" -Value "$exePath,0"
Set-ItemProperty -Path $uninstallKey -Name "URLInfoAbout" -Value "https://github.com/mstrhakr/printmaster"
Set-ItemProperty -Path $uninstallKey -Name "HelpLink" -Value "https://github.com/mstrhakr/printmaster"
Show-Success "Registered in Add/Remove Programs"

Show-Progress -Percent 85 -Message "Starting service..."
Show-Info "Starting PrintMaster Agent service..."

$startProc = Start-Process -FilePath $exePath -ArgumentList "--service","start","--silent" -Wait -PassThru -NoNewWindow
if ($startProc.ExitCode -ne 0) {
	Show-Warning "Service start returned exit code $($startProc.ExitCode)"
}

# Step 7: Clean up
Show-Progress -Percent 90 -Message "Cleaning up..."
Remove-Item -Path $tempExePath -Force -ErrorAction SilentlyContinue
Remove-Item -Path $tempDir -Force -Recurse -ErrorAction SilentlyContinue
Show-Success "Temporary files removed"

# Step 8: Verify service
Show-Progress -Percent 95 -Message "Verifying installation..."

Start-Sleep -Seconds 2
$svc = Get-Service -Name "PrintMasterAgent" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
	Show-Success "Service is running"
} elseif ($svc) {
	Show-Info "Service status: $($svc.Status)"
	Show-Info "Attempting to start service..."
	Start-Service -Name "PrintMasterAgent" -ErrorAction SilentlyContinue
	Start-Sleep -Seconds 2
	$svc = Get-Service -Name "PrintMasterAgent" -ErrorAction SilentlyContinue
	if ($svc -and $svc.Status -eq 'Running') {
		Show-Success "Service started"
	} else {
		Show-Warning "Service may need manual start"
	}
} else {
	Show-Error "Service not found after installation"
	Show-CompletionBox -Success $false -Message "Service Not Found"
	exit 1
}

Show-Progress -Percent 100 -Message "Complete!"

# Show completion
Show-CompletionBox -Success $true -Message "Installation Complete!"

Write-Host ""
Show-Info "Executable:    $exePath"
Show-Info "Configuration: $configPath"
Show-Info "Logs folder:   $(Join-Path $configDir 'logs')"
Show-Info "Web UI:        https://localhost:8443"
Write-Host ""
`

const unixBootstrapScript = `#!/bin/sh
SERVER='%s'
TOKEN='%s'
set -e

case "$SERVER" in
	https://*) ;;
	*) echo "Error: server URL must use HTTPS; configure server.external_url." >&2; exit 1 ;;
esac

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
	echo "Error: This installer must be run as root." >&2
	echo "Usage: sudo sh -c \"\$(curl -fsSL '<URL>')\"" >&2
	exit 1
fi

REPO_BASE="https://mstrhakr.github.io/printmaster"

# Detect distro family from /etc/os-release
DISTRO_FAMILY=""
if [ -f /etc/os-release ]; then
	. /etc/os-release
	case "$ID" in
		debian|ubuntu|raspbian|linuxmint|pop|elementary|zorin|kali|parrot)
			DISTRO_FAMILY="debian"
			;;
		fedora|rhel|centos|rocky|alma|ol|amzn)
			DISTRO_FAMILY="rhel"
			;;
		opensuse*|sles)
			DISTRO_FAMILY="suse"
			;;
	esac
	# Also check ID_LIKE as fallback
	if [ -z "$DISTRO_FAMILY" ] && [ -n "$ID_LIKE" ]; then
		case "$ID_LIKE" in
			*debian*|*ubuntu*) DISTRO_FAMILY="debian" ;;
			*rhel*|*fedora*|*centos*) DISTRO_FAMILY="rhel" ;;
			*suse*) DISTRO_FAMILY="suse" ;;
		esac
	fi
fi

echo "Detected distro: ${ID:-unknown} (family: ${DISTRO_FAMILY:-unknown})"

# Function to configure agent after install
configure_agent() {
	mkdir -p /etc/printmaster
	AGENT_NAME="$(hostname 2>/dev/null || echo 'linux-agent')"
	cat > /etc/printmaster/config.toml <<EOF
[server]
enabled = true
url = "$SERVER"
name = "$AGENT_NAME"
token = "$TOKEN"
insecure_skip_verify = false
EOF
	chmod 600 /etc/printmaster/config.toml
	echo "Configuration: /etc/printmaster/config.toml"
}

# Function for direct binary install (fallback)
install_binary() {
	echo "Installing via direct binary download..."
	
	# Detect architecture
	ARCH="$(uname -m)"
	case "$ARCH" in
		x86_64)  ARCH="amd64" ;;
		aarch64) ARCH="arm64" ;;
		armv7l)  ARCH="armv7" ;;
	esac

	echo "Downloading agent (linux/$ARCH)..."
	curl -fsSL "$SERVER/api/v1/agents/download/latest?platform=linux&arch=$ARCH&proxy=1" -o /usr/local/bin/pm-agent || exit 1
	chmod +x /usr/local/bin/pm-agent

	# Fix SELinux context if SELinux is enabled (required for Fedora/RHEL/CentOS)
	if command -v restorecon >/dev/null 2>&1; then
		restorecon -v /usr/local/bin/pm-agent 2>/dev/null || true
	fi

	configure_agent

	# Install systemd unit if available
	if command -v systemctl >/dev/null 2>&1; then
		cat >/etc/systemd/system/printmaster-agent.service <<EOL
[Unit]
Description=PrintMaster Agent
After=network.target

[Service]
ExecStart=/usr/local/bin/pm-agent --config /etc/printmaster/config.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOL
		systemctl daemon-reload || true
		systemctl enable --now printmaster-agent || true
		echo "PrintMaster Agent service installed and started."
		echo "Check status: systemctl status printmaster-agent"
	else
		echo "systemd not found. Starting agent manually..."
		/usr/local/bin/pm-agent --config /etc/printmaster/config.toml &
	fi
}

# Install based on detected distro family
case "$DISTRO_FAMILY" in
	debian)
		if command -v apt-get >/dev/null 2>&1; then
			echo "Installing via APT (Debian/Ubuntu family)..."
			APT_KEYRING="/usr/share/keyrings/printmaster.gpg"
			if command -v gpg >/dev/null 2>&1 && install -d -m 0755 /usr/share/keyrings && curl -fsSL "$REPO_BASE/gpg.key" | gpg --dearmor --yes -o "$APT_KEYRING"; then
				chmod 0644 "$APT_KEYRING"
				echo "deb [signed-by=$APT_KEYRING] $REPO_BASE stable main" > /etc/apt/sources.list.d/printmaster.list
				if apt-get update -qq && apt-get install -y printmaster-agent; then
					configure_agent
					systemctl restart printmaster-agent 2>/dev/null || true
					echo "PrintMaster Agent installed via APT."
					echo "Check status: systemctl status printmaster-agent"
					exit 0
				fi
			else
				echo "APT signature verification setup failed; falling back to the binary installer."
			fi
			echo "APT install failed, falling back to binary..."
			rm -f /etc/apt/sources.list.d/printmaster.list
		fi
		;;
	rhel)
		# Prefer DNF over YUM on modern systems
		if command -v dnf >/dev/null 2>&1; then
			echo "Installing via DNF (Fedora/RHEL family)..."
			curl -fsSL "$REPO_BASE/printmaster.repo" -o /etc/yum.repos.d/printmaster.repo
			if dnf install -y printmaster-agent; then
				configure_agent
				systemctl restart printmaster-agent 2>/dev/null || true
				echo "PrintMaster Agent installed via DNF."
				echo "Check status: systemctl status printmaster-agent"
				exit 0
			fi
			echo "DNF install failed, falling back to binary..."
			rm -f /etc/yum.repos.d/printmaster.repo
		elif command -v yum >/dev/null 2>&1; then
			echo "Installing via YUM (RHEL/CentOS family)..."
			curl -fsSL "$REPO_BASE/printmaster.repo" -o /etc/yum.repos.d/printmaster.repo
			if yum install -y printmaster-agent; then
				configure_agent
				systemctl restart printmaster-agent 2>/dev/null || true
				echo "PrintMaster Agent installed via YUM."
				echo "Check status: systemctl status printmaster-agent"
				exit 0
			fi
			echo "YUM install failed, falling back to binary..."
			rm -f /etc/yum.repos.d/printmaster.repo
		fi
		;;
	suse)
		if command -v zypper >/dev/null 2>&1; then
			echo "Installing via Zypper (openSUSE/SLES family)..."
			# Note: Zypper repo support would need to be added to the repo
			echo "Zypper repository not yet available, using binary install..."
		fi
		;;
esac

# Fallback to direct binary install (unknown distro or package install failed)
echo "Using direct binary install..."
install_binary
`

func normalizePlatform(input string) string {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "win", "windows", "windows_nt":
		return "windows"
	case "mac", "darwin", "osx":
		return "darwin"
	case "linux", "":
		return "linux"
	default:
		return strings.ToLower(strings.TrimSpace(input))
	}
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// buildReleaseAssetURL constructs an asset URL from the fixed release origin.
// The loopback exception exists only for in-process httptest servers; an
// externally configured release origin is never accepted.
func buildReleaseAssetURL(releaseTag, asset string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(releaseAssetBaseURL))
	if err != nil || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return "", fmt.Errorf("invalid release asset base URL")
	}
	host := strings.ToLower(base.Hostname())
	if !(base.Scheme == "https" && host == "github.com" && base.Port() == "") {
		// Tests use a local HTTP server.  Keep that narrow exception while
		// rejecting any other runtime origin that could become an SSRF target.
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", fmt.Errorf("release asset origin must be github.com over HTTPS")
		}
		if base.Scheme != "http" && base.Scheme != "https" {
			return "", fmt.Errorf("release asset origin must use HTTP or HTTPS")
		}
	}

	base.Path = strings.TrimRight(base.Path, "/") + "/" + url.PathEscape(releaseTag) + "/" + url.PathEscape(asset)
	base.RawPath = ""
	return base.String(), nil
}

func safeReleaseVersion(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" || len(version) > 64 {
		return false
	}
	for _, r := range version {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		if r != '.' && r != '-' && r != '+' && r != '_' {
			return false
		}
	}
	return true
}

// handleAgentDownloadLatest redirects to the latest compatible agent binary
// on GitHub Releases. Query params accepted: ?platform=linux|windows|darwin&arch=amd64|arm64
// If server version was supplied by main via SetServerVersion, that is used;
// otherwise the handler attempts to read `server/VERSION` from the working
// directory. If no version can be determined, a 404 is returned.
func handleAgentDownloadLatest(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	platform := strings.ToLower(strings.TrimSpace(q.Get("platform")))
	arch := strings.ToLower(strings.TrimSpace(q.Get("arch")))
	proxyParam := strings.ToLower(q.Get("proxy"))
	proxyDownload := proxyParam == "1" || proxyParam == "true" || proxyParam == "yes"
	if platform == "" {
		platform = "linux"
	}
	if arch == "" {
		arch = "amd64"
	}
	switch platform {
	case "linux":
		platform = "linux"
	case "win", "windows", "windows_nt":
		platform = "windows"
	case "mac", "darwin", "osx":
		platform = "darwin"
	default:
		http.Error(w, "unsupported platform", http.StatusBadRequest)
		return
	}
	if arch != "amd64" && arch != "arm64" {
		http.Error(w, "unsupported architecture", http.StatusBadRequest)
		return
	}
	format := strings.ToLower(strings.TrimSpace(q.Get("format")))
	if format == "" {
		format = "exe"
	}
	if format != "exe" && format != "msi" {
		http.Error(w, "unsupported agent package format", http.StatusBadRequest)
		return
	}
	if platform != "windows" && format == "msi" {
		http.Error(w, "MSI format is only available for Windows", http.StatusBadRequest)
		return
	}

	ver := serverVersion
	if ver == "" {
		if b, err := os.ReadFile("server/VERSION"); err == nil {
			ver = strings.TrimSpace(string(b))
		}
	}
	if ver == "" {
		http.Error(w, "server version unknown", http.StatusNotFound)
		return
	}
	if !safeReleaseVersion(ver) {
		http.Error(w, "server version is invalid", http.StatusInternalServerError)
		return
	}

	tag := ver
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	releaseTag := "agent-" + tag

	// Select the suffix from constants after the allowlists above.  Keeping
	// user input out of the URL path itself prevents path traversal and SSRF
	// taint from reaching the download client.
	var suffix string
	switch platform {
	case "linux":
		if arch == "amd64" {
			suffix = "-linux-amd64"
		} else {
			suffix = "-linux-arm64"
		}
	case "windows":
		if arch == "amd64" {
			suffix = "-windows-amd64"
		} else {
			suffix = "-windows-arm64"
		}
	case "darwin":
		if arch == "amd64" {
			suffix = "-darwin-amd64"
		} else {
			suffix = "-darwin-arm64"
		}
	}
	ext := ""
	if platform == "windows" {
		if format == "msi" {
			ext = ".msi"
		} else {
			ext = ".exe"
		}
	}
	asset := "printmaster-agent-" + tag + suffix + ext
	redirectURL, err := buildReleaseAssetURL(releaseTag, asset)
	if err != nil {
		http.Error(w, "release asset source is not configured safely", http.StatusInternalServerError)
		return
	}

	if !proxyDownload {
		// Use 302/Found to allow capable clients to follow to GitHub directly.
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
	if !acquireAgentDownload(r.Context()) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "agent download capacity is temporarily full", http.StatusTooManyRequests)
		return
	}
	defer releaseAgentDownload()

	// Fall back to proxying the download through the server for older clients
	// (notably legacy PowerShell) that cannot negotiate GitHub's TLS/SNI
	// requirements.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, redirectURL, nil)
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("User-Agent", fmt.Sprintf("printmaster-server/%s", ver))
	resp, err := releaseDownloadClient.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream download failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("upstream responded with %s", resp.Status), http.StatusBadGateway)
		return
	}
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		size, parseErr := strconv.ParseInt(contentLength, 10, 64)
		if parseErr != nil || size < 0 || size > maxAgentDownloadBytes {
			http.Error(w, "upstream agent package is too large", http.StatusBadGateway)
			return
		}
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		w.Header().Set("Content-Disposition", cd)
	} else {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", asset))
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	// Unknown-length responses are still capped. If the upstream sends more
	// than the limit, the client receives a truncated package and must reject it
	// rather than allowing an unbounded response stream.
	if _, err := io.Copy(w, io.LimitReader(resp.Body, maxAgentDownloadBytes)); err != nil {
		// We cannot change the response at this point; best-effort copy only.
		return
	}
}
