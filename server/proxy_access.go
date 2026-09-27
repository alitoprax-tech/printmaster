package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const printerProxyCookie = "__Host-pm_proxy"
const printerProxyTTL = 5 * time.Minute

type printerProxyGrant struct {
	userID   int64
	scope    string
	tenantID string
	agentID  string
	deviceID string
	expires  time.Time
}

var printerProxyGrants = struct {
	sync.Mutex
	tickets  map[[32]byte]printerProxyGrant
	sessions map[[32]byte]printerProxyGrant
}{tickets: make(map[[32]byte]printerProxyGrant), sessions: make(map[[32]byte]printerProxyGrant)}

func proxyScope(kind, id string) (string, error) {
	if kind != "agent" && kind != "device" {
		return "", errors.New("invalid proxy resource")
	}
	if id == "" || len(id) > 128 {
		return "", errors.New("invalid proxy resource")
	}
	for _, c := range id {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return "", errors.New("invalid proxy resource")
		}
	}
	return kind + "/" + id, nil
}

func requestProxyScope(path string) string {
	var kind, remainder string
	switch {
	case strings.HasPrefix(path, "/api/v1/proxy/agent/"):
		kind, remainder = "agent", strings.TrimPrefix(path, "/api/v1/proxy/agent/")
	case strings.HasPrefix(path, "/api/v1/proxy/device/"):
		kind, remainder = "device", strings.TrimPrefix(path, "/api/v1/proxy/device/")
	case strings.HasPrefix(path, "/proxy/"):
		kind, remainder = "device", strings.TrimPrefix(path, "/proxy/")
	default:
		return ""
	}
	id, _, _ := strings.Cut(remainder, "/")
	scope, _ := proxyScope(kind, id)
	return scope
}

func pruneProxyGrants(now time.Time) {
	for id, grant := range printerProxyGrants.tickets {
		if !now.Before(grant.expires) {
			delete(printerProxyGrants.tickets, id)
		}
	}
	for id, grant := range printerProxyGrants.sessions {
		if !now.Before(grant.expires) {
			delete(printerProxyGrants.sessions, id)
		}
	}
}

func printerProxyBinding(ctx context.Context, scope string) (printerProxyGrant, error) {
	kind, id, ok := strings.Cut(scope, "/")
	if !ok || serverStore == nil {
		return printerProxyGrant{}, errors.New("invalid proxy scope")
	}
	if kind == "device" {
		device, err := serverStore.GetDevice(ctx, id)
		if err != nil || device == nil || device.AgentID == "" {
			return printerProxyGrant{}, errors.New("proxy device unavailable")
		}
		agent, err := serverStore.GetAgent(ctx, device.AgentID)
		if err != nil || agent == nil || agent.TenantID == "" {
			return printerProxyGrant{}, errors.New("proxy Agent unavailable")
		}
		return printerProxyGrant{scope: scope, tenantID: agent.TenantID, agentID: agent.AgentID, deviceID: id}, nil
	}
	if kind == "agent" {
		agent, err := serverStore.GetAgent(ctx, id)
		if err != nil || agent == nil || agent.TenantID == "" {
			return printerProxyGrant{}, errors.New("proxy Agent unavailable")
		}
		return printerProxyGrant{scope: scope, tenantID: agent.TenantID, agentID: agent.AgentID}, nil
	}
	return printerProxyGrant{}, errors.New("invalid proxy scope")
}

func mintPrinterTicket(ctx context.Context, userID int64, scope string) (string, bool) {
	binding, err := printerProxyBinding(ctx, scope)
	if err != nil {
		return "", false
	}
	token := rand.Text()
	key := sha256.Sum256([]byte(token))
	now := time.Now()
	printerProxyGrants.Lock()
	defer printerProxyGrants.Unlock()
	pruneProxyGrants(now)
	if len(printerProxyGrants.tickets) >= 2048 {
		return "", false
	}
	binding.userID, binding.expires = userID, now.Add(time.Minute)
	printerProxyGrants.tickets[key] = binding
	return token, true
}

func printerTicketURL(r *http.Request, ticket string) string {
	q := r.URL.Query()
	q.Del("ticket")
	q.Set("ticket", ticket)
	return configuredTrustExternalURL(serverConfig, trustDomainPrinterProxy) + r.URL.Path + "?" + q.Encode()
}

// Older dashboard links point to the former same-origin proxy path. On the
// admin host they only redirect; no printer-controlled byte is rendered there.
func handleAdminProxyRedirect(w http.ResponseWriter, r *http.Request) {
	if !browserProxyEnabled() || !trustDomainsEnforced() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scope := requestProxyScope(r.URL.Path)
	p := getPrincipal(r)
	if scope == "" || p == nil || p.User == nil {
		http.NotFound(w, r)
		return
	}
	ticket, ok := mintPrinterTicket(r.Context(), p.User.ID, scope)
	if !ok {
		http.Error(w, "proxy busy", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, printerTicketURL(r, ticket), http.StatusSeeOther)
}

// An admin-authenticated browser requests a scoped, one-use ticket. The
// printer origin never receives the admin session cookie or bearer token.
func handleProxyAccess(w http.ResponseWriter, r *http.Request) {
	if !browserProxyEnabled() || !trustDomainsEnforced() {
		http.Error(w, "printer proxy is disabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	if err := decodeJSONBody(r, &input); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	scope, err := proxyScope(input.Kind, input.ID)
	if err != nil {
		http.Error(w, "invalid proxy resource", http.StatusBadRequest)
		return
	}
	principal := getPrincipal(r)
	if principal == nil || principal.User == nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	// Authorization and tenant checks are repeated on every actual proxy
	// request. Issuance alone does not grant access to a different resource.
	token, ok := mintPrinterTicket(r.Context(), principal.User.ID, scope)
	if !ok {
		http.Error(w, "proxy busy", http.StatusServiceUnavailable)
		return
	}
	path := "/api/v1/proxy/" + scope + "/"
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"url": configuredTrustExternalURL(serverConfig, trustDomainPrinterProxy) + path + "?ticket=" + url.QueryEscape(token)})
}

func requirePrinterProxyAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !browserProxyEnabled() || !trustDomainsEnforced() || requireTrustDomain(r, trustDomainPrinterProxy) != nil {
			http.NotFound(w, r)
			return
		}
		scope := requestProxyScope(r.URL.Path)
		if scope == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if ticket := r.URL.Query().Get("ticket"); ticket != "" {
			if r.Method != http.MethodGet || len(ticket) > 256 {
				http.Error(w, "invalid proxy ticket", http.StatusForbidden)
				return
			}
			key := sha256.Sum256([]byte(ticket))
			printerProxyGrants.Lock()
			grant, found := printerProxyGrants.tickets[key]
			delete(printerProxyGrants.tickets, key)
			printerProxyGrants.Unlock()
			binding, bindErr := printerProxyBinding(r.Context(), scope)
			if !found || time.Now().After(grant.expires) || grant.scope != scope || bindErr != nil || !samePrinterProxyBinding(grant, binding) {
				http.Error(w, "invalid proxy ticket", http.StatusForbidden)
				return
			}
			session := rand.Text()
			printerProxyGrants.Lock()
			pruneProxyGrants(time.Now())
			if len(printerProxyGrants.sessions) >= 8192 {
				printerProxyGrants.Unlock()
				http.Error(w, "proxy busy", http.StatusServiceUnavailable)
				return
			}
			grant.expires = time.Now().Add(printerProxyTTL)
			printerProxyGrants.sessions[sha256.Sum256([]byte(session))] = grant
			printerProxyGrants.Unlock()
			http.SetCookie(w, &http.Cookie{Name: printerProxyCookie, Value: session, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(printerProxyTTL.Seconds())})
			clean := *r.URL
			query := clean.Query()
			query.Del("ticket")
			clean.RawQuery = query.Encode()
			http.Redirect(w, r, clean.RequestURI(), http.StatusSeeOther)
			return
		}
		cookie, err := r.Cookie(printerProxyCookie)
		if err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		printerProxyGrants.Lock()
		grant, found := printerProxyGrants.sessions[sha256.Sum256([]byte(cookie.Value))]
		printerProxyGrants.Unlock()
		binding, bindErr := printerProxyBinding(r.Context(), scope)
		if !found || time.Now().After(grant.expires) || grant.scope != scope || bindErr != nil || !samePrinterProxyBinding(grant, binding) {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		user, err := serverStore.GetUserByID(r.Context(), grant.userID)
		if err != nil || user == nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		// Neither admin cookies nor Agent certificates can make a proxy principal.
		next.ServeHTTP(w, r.WithContext(contextWithPrincipal(r.Context(), user)))
	}
}

func samePrinterProxyBinding(a, b printerProxyGrant) bool {
	return a.scope == b.scope && a.tenantID != "" && a.tenantID == b.tenantID && a.agentID != "" && a.agentID == b.agentID && a.deviceID == b.deviceID
}
