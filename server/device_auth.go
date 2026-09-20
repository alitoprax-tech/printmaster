package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	authz "printmaster/server/authz"
	"printmaster/server/storage"
)

const (
	deviceAuthRequestTTL       = 10 * time.Minute
	deviceAuthJoinTokenTTL     = 15 // minutes
	deviceAuthCleanupInterval  = 1 * time.Minute
	deviceAuthCodeLength       = 6
	deviceAuthPollTokenEntropy = 32
	deviceAuthMaxRequests      = 4096
	deviceAuthMaxAgentID       = 128
	deviceAuthMaxAgentName     = 200
	deviceAuthMaxVersion       = 128
	deviceAuthMaxHostname      = 255
	deviceAuthMaxPlatform      = 64
	deviceAuthMaxReason        = 500
)

type deviceAuthStatus string

const (
	deviceAuthStatusPending  deviceAuthStatus = "pending"
	deviceAuthStatusApproved deviceAuthStatus = "approved"
	deviceAuthStatusRejected deviceAuthStatus = "rejected"
	deviceAuthStatusExpired  deviceAuthStatus = "expired"
)

type deviceAuthMetadata struct {
	AgentID      string `json:"agent_id"`
	AgentName    string `json:"agent_name"`
	AgentVersion string `json:"agent_version"`
	Hostname     string `json:"hostname"`
	Platform     string `json:"platform"`
	ClientIP     string `json:"client_ip"`
}

type deviceAuthRequest struct {
	Code      string
	PollToken string
	Status    deviceAuthStatus

	Metadata     deviceAuthMetadata
	AssignedName string

	RequestedAt time.Time
	ExpiresAt   time.Time

	TenantID   string
	TenantName string

	ApprovedAt         time.Time
	ApprovedBy         string
	JoinToken          string
	joinTokenDelivered bool

	RejectedAt time.Time
	RejectedBy string

	Message string
}

type deviceAuthStore struct {
	mu     sync.Mutex
	byCode map[string]*deviceAuthRequest
	byPoll map[string]*deviceAuthRequest
}

func newDeviceAuthStore() *deviceAuthStore {
	return &deviceAuthStore{
		byCode: make(map[string]*deviceAuthRequest),
		byPoll: make(map[string]*deviceAuthRequest),
	}
}

var (
	deviceAuthStoreMu sync.Mutex
	deviceAuthInst    *deviceAuthStore
	deviceAuthRate    = struct {
		sync.Mutex
		entries map[string]deviceAuthRateEntry
	}{entries: make(map[string]deviceAuthRateEntry)}
)

type deviceAuthRateEntry struct {
	windowStart time.Time
	count       int
}

const (
	deviceAuthRateWindow  = time.Minute
	deviceAuthStartLimit  = 10
	deviceAuthRateMaxKeys = 4096
)

func allowDeviceAuthStart(r *http.Request) bool {
	now := time.Now().UTC()
	key := publicClientKey(r)
	deviceAuthRate.Lock()
	defer deviceAuthRate.Unlock()
	for k, entry := range deviceAuthRate.entries {
		if now.Sub(entry.windowStart) >= deviceAuthRateWindow {
			delete(deviceAuthRate.entries, k)
		}
	}
	entry, ok := deviceAuthRate.entries[key]
	if !ok {
		if len(deviceAuthRate.entries) >= deviceAuthRateMaxKeys {
			return false
		}
		deviceAuthRate.entries[key] = deviceAuthRateEntry{windowStart: now, count: 1}
		return true
	}
	if entry.count >= deviceAuthStartLimit {
		return false
	}
	entry.count++
	deviceAuthRate.entries[key] = entry
	return true
}

func publicClientKey(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	return extractIPFromAddr(strings.TrimSpace(r.RemoteAddr))
}

func ensureDeviceAuthStore() *deviceAuthStore {
	deviceAuthStoreMu.Lock()
	defer deviceAuthStoreMu.Unlock()
	if deviceAuthInst == nil {
		deviceAuthInst = newDeviceAuthStore()
		go deviceAuthInst.cleanupLoop()
	}
	return deviceAuthInst
}

func (s *deviceAuthStore) cleanupLoop() {
	ticker := time.NewTicker(deviceAuthCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		s.cleanupExpired()
	}
}

func (s *deviceAuthStore) cleanupExpired() {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, req := range s.byCode {
		if now.After(req.ExpiresAt) {
			delete(s.byCode, key)
			delete(s.byPoll, req.PollToken)
		}
	}
}

func (s *deviceAuthStore) Create(meta deviceAuthMetadata) *deviceAuthRequest {
	if s == nil {
		return nil
	}
	now := time.Now().UTC()
	code := generateDeviceAuthCode()
	pollToken := generateDeviceAuthPollToken()
	// Device authorization values are bearer credentials. If the operating
	// system cannot provide cryptographic randomness, fail closed instead of
	// issuing a predictable code or timestamp-based token.
	if code == "" || pollToken == "" {
		return nil
	}
	req := &deviceAuthRequest{
		Code:         code,
		PollToken:    pollToken,
		Status:       deviceAuthStatusPending,
		Metadata:     meta,
		AssignedName: strings.TrimSpace(meta.AgentName),
		RequestedAt:  now,
		ExpiresAt:    now.Add(deviceAuthRequestTTL),
	}
	s.mu.Lock()
	// Bound the in-memory authorization queue. Expired requests are removed
	// before enforcing the cap so a burst cannot turn this endpoint into a
	// process-memory exhaustion primitive.
	for key, existing := range s.byCode {
		if existing == nil || now.After(existing.ExpiresAt) {
			delete(s.byCode, key)
			if existing != nil {
				delete(s.byPoll, existing.PollToken)
			}
		}
	}
	if len(s.byCode) >= deviceAuthMaxRequests {
		s.mu.Unlock()
		return nil
	}
	s.byCode[strings.ToUpper(req.Code)] = req
	s.byPoll[req.PollToken] = req
	s.mu.Unlock()
	return req
}

func (s *deviceAuthStore) snapshot(code string) (*deviceAuthRequest, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.byCode[strings.ToUpper(code)]
	if !ok {
		return nil, false
	}
	if req.Status != deviceAuthStatusExpired && time.Now().UTC().After(req.ExpiresAt) {
		req.Status = deviceAuthStatusExpired
		req.Message = "Request expired"
		delete(s.byCode, strings.ToUpper(code))
		delete(s.byPoll, req.PollToken)
		return nil, false
	}
	clone := *req
	return &clone, true
}

func (s *deviceAuthStore) getByPoll(pollToken string) (*deviceAuthRequest, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.byPoll[pollToken]
	if !ok {
		return nil, false
	}
	if req.Status != deviceAuthStatusExpired && time.Now().UTC().After(req.ExpiresAt) {
		req.Status = deviceAuthStatusExpired
		req.Message = "Request expired"
		delete(s.byCode, strings.ToUpper(req.Code))
		delete(s.byPoll, pollToken)
	}
	if !ok || req == nil {
		return req, ok
	}
	clone := *req
	if clone.Status == deviceAuthStatusApproved {
		if req.joinTokenDelivered {
			clone.JoinToken = ""
		} else {
			req.joinTokenDelivered = true
		}
	}
	return &clone, ok
}

func (s *deviceAuthStore) approve(code, tenantID, tenantName, agentName, approver string, joinToken string) (*deviceAuthRequest, error) {
	if s == nil {
		return nil, errors.New("store unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.byCode[strings.ToUpper(code)]
	if !ok {
		return nil, errors.New("request not found")
	}
	if time.Now().UTC().After(req.ExpiresAt) {
		req.Status = deviceAuthStatusExpired
		req.Message = "Request expired"
		delete(s.byCode, strings.ToUpper(code))
		delete(s.byPoll, req.PollToken)
		return nil, errors.New("request expired")
	}
	if req.Status == deviceAuthStatusRejected {
		return nil, errors.New("request already rejected")
	}
	if req.Status == deviceAuthStatusApproved {
		return req, nil
	}
	req.Status = deviceAuthStatusApproved
	req.TenantID = tenantID
	req.TenantName = tenantName
	if strings.TrimSpace(agentName) != "" {
		req.AssignedName = strings.TrimSpace(agentName)
	}
	req.ApprovedAt = time.Now().UTC()
	req.ApprovedBy = approver
	req.JoinToken = joinToken
	req.Message = "Approved"
	return req, nil
}

func (s *deviceAuthStore) reject(code, reason, actor string) (*deviceAuthRequest, error) {
	if s == nil {
		return nil, errors.New("store unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.byCode[strings.ToUpper(code)]
	if !ok {
		return nil, errors.New("request not found")
	}
	if time.Now().UTC().After(req.ExpiresAt) {
		req.Status = deviceAuthStatusExpired
		req.Message = "Request expired"
		delete(s.byCode, strings.ToUpper(code))
		delete(s.byPoll, req.PollToken)
		return nil, errors.New("request expired")
	}
	if req.Status == deviceAuthStatusApproved {
		return nil, errors.New("request already approved")
	}
	if req.Status == deviceAuthStatusRejected {
		return nil, errors.New("request already rejected")
	}
	req.Status = deviceAuthStatusRejected
	req.Message = reason
	req.RejectedAt = time.Now().UTC()
	req.RejectedBy = actor
	return req, nil
}

func generateDeviceAuthCode() string {
	alphabet := []rune("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")
	var b strings.Builder
	b.Grow(deviceAuthCodeLength)
	for i := 0; i < deviceAuthCodeLength; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return ""
		}
		b.WriteRune(alphabet[idx.Int64()])
	}
	return b.String()
}

func generateDeviceAuthPollToken() string {
	buf := make([]byte, deviceAuthPollTokenEntropy)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func handleAgentDeviceAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if serverStore == nil {
		http.Error(w, "server not ready", http.StatusServiceUnavailable)
		return
	}
	if !allowDeviceAuthStart(r) {
		http.Error(w, "device authorization rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	var in struct {
		AgentID      string `json:"agent_id"`
		AgentName    string `json:"agent_name"`
		AgentVersion string `json:"agent_version"`
		Hostname     string `json:"hostname"`
		Platform     string `json:"platform"`
	}
	if err := decodeJSONBody(r, &in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(in.AgentID) == "" {
		http.Error(w, "agent_id required", http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(in.AgentID)) > deviceAuthMaxAgentID ||
		len(strings.TrimSpace(in.AgentName)) > deviceAuthMaxAgentName ||
		len(strings.TrimSpace(in.AgentVersion)) > deviceAuthMaxVersion ||
		len(strings.TrimSpace(in.Hostname)) > deviceAuthMaxHostname ||
		len(strings.TrimSpace(in.Platform)) > deviceAuthMaxPlatform {
		http.Error(w, "device metadata too long", http.StatusBadRequest)
		return
	}
	meta := deviceAuthMetadata{
		AgentID:      strings.TrimSpace(in.AgentID),
		AgentName:    strings.TrimSpace(in.AgentName),
		AgentVersion: strings.TrimSpace(in.AgentVersion),
		Hostname:     strings.TrimSpace(in.Hostname),
		Platform:     strings.TrimSpace(in.Platform),
		ClientIP:     extractClientIP(r),
	}
	req := ensureDeviceAuthStore().Create(meta)
	if req == nil {
		http.Error(w, "device authorization queue is full", http.StatusTooManyRequests)
		return
	}
	authorizeURL := fmt.Sprintf("%s/device-auth/%s", buildExternalURL(r), url.PathEscape(strings.ToUpper(req.Code)))
	resp := map[string]interface{}{
		"success":       true,
		"code":          req.Code,
		"poll_token":    req.PollToken,
		"expires_at":    req.ExpiresAt.Format(time.RFC3339),
		"authorize_url": authorizeURL,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleAgentDeviceAuthPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		PollToken string `json:"poll_token"`
	}
	if err := decodeJSONBody(r, &in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(in.PollToken) == "" {
		http.Error(w, "poll_token required", http.StatusBadRequest)
		return
	}
	req, ok := ensureDeviceAuthStore().getByPoll(strings.TrimSpace(in.PollToken))
	if !ok || req == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	resp := map[string]interface{}{
		"success": true,
		"status":  req.Status,
		"code":    req.Code,
		"message": req.Message,
	}
	if req.Status == deviceAuthStatusApproved {
		resp["join_token"] = req.JoinToken
		resp["tenant_id"] = req.TenantID
		resp["agent_name"] = req.AssignedName
	}
	if req.Status == deviceAuthStatusRejected {
		resp["reason"] = req.Message
	}
	if req.Status == deviceAuthStatusExpired {
		resp["reason"] = "expired"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleDeviceAuthRequestRoute(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/device-auth/requests/")
	rest = strings.Trim(rest, "/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	code := strings.ToUpper(parts[0])
	store := ensureDeviceAuthStore()
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		handleDeviceAuthRequestGet(w, r, store, code)
	case len(parts) == 2 && parts[1] == "approve" && r.Method == http.MethodPost:
		handleDeviceAuthApprove(w, r, store, code)
	case len(parts) == 2 && parts[1] == "reject" && r.Method == http.MethodPost:
		handleDeviceAuthReject(w, r, store, code)
	default:
		http.NotFound(w, r)
	}
}

func handleDeviceAuthRequestGet(w http.ResponseWriter, r *http.Request, store *deviceAuthStore, code string) {
	snapshot, ok := store.snapshot(code)
	if !ok || snapshot == nil {
		http.NotFound(w, r)
		return
	}
	resource := authz.ResourceRef{}
	if snapshot.TenantID != "" {
		resource.TenantIDs = []string{snapshot.TenantID}
	}
	if !authorizeOrReject(w, r, authz.ActionAgentsWrite, resource) {
		return
	}
	tenants, err := listAccessibleTenants(r)
	if err != nil {
		http.Error(w, "failed to list tenants", http.StatusInternalServerError)
		return
	}
	resp := map[string]interface{}{
		"code":         snapshot.Code,
		"status":       snapshot.Status,
		"message":      snapshot.Message,
		"requested_at": snapshot.RequestedAt.Format(time.RFC3339),
		"expires_at":   snapshot.ExpiresAt.Format(time.RFC3339),
		"agent": map[string]string{
			"id":        snapshot.Metadata.AgentID,
			"name":      snapshot.Metadata.AgentName,
			"version":   snapshot.Metadata.AgentVersion,
			"hostname":  snapshot.Metadata.Hostname,
			"platform":  snapshot.Metadata.Platform,
			"client_ip": snapshot.Metadata.ClientIP,
		},
		"tenants": tenants,
	}
	if snapshot.AssignedName != "" {
		resp["assigned_name"] = snapshot.AssignedName
	}
	if !snapshot.ApprovedAt.IsZero() {
		resp["approved_at"] = snapshot.ApprovedAt.Format(time.RFC3339)
		resp["approved_by"] = snapshot.ApprovedBy
	}
	if snapshot.TenantID != "" {
		resp["tenant_id"] = snapshot.TenantID
		resp["tenant_name"] = snapshot.TenantName
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type tenantOption struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func listAccessibleTenants(r *http.Request) ([]tenantOption, error) {
	if serverStore == nil {
		return nil, errors.New("store unavailable")
	}
	list, err := serverStore.ListTenants(r.Context())
	if err != nil {
		return nil, err
	}
	principal := getPrincipal(r)
	allowed := make([]tenantOption, 0, len(list))
	for _, t := range list {
		if principal != nil && !principal.CanAccessTenant(t.ID) {
			continue
		}
		allowed = append(allowed, tenantOption{ID: t.ID, Name: t.Name})
	}
	return allowed, nil
}

func handleDeviceAuthApprove(w http.ResponseWriter, r *http.Request, store *deviceAuthStore, code string) {
	principal := getPrincipal(r)
	if principal == nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	snapshot, ok := store.snapshot(code)
	if !ok || snapshot == nil || snapshot.Status != deviceAuthStatusPending {
		http.Error(w, "request not found or already reviewed", http.StatusConflict)
		return
	}
	var in struct {
		TenantID  string `json:"tenant_id"`
		AgentName string `json:"agent_name"`
	}
	if err := decodeJSONBody(r, &in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(in.TenantID) == "" {
		http.Error(w, "tenant_id required", http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(in.AgentName)) > deviceAuthMaxAgentName {
		http.Error(w, "agent_name too long", http.StatusBadRequest)
		return
	}
	if !authorizeOrReject(w, r, authz.ActionAgentsWrite, authz.ResourceRef{TenantIDs: []string{strings.TrimSpace(in.TenantID)}}) {
		return
	}
	ctx := r.Context()
	var tenantName string
	if serverStore != nil {
		if tenant, err := serverStore.GetTenant(ctx, strings.TrimSpace(in.TenantID)); err == nil && tenant != nil {
			tenantName = tenant.Name
		}
	}
	if tenantName == "" {
		tenantName = strings.TrimSpace(in.TenantID)
	}
	_, rawToken, err := serverStore.CreateJoinToken(ctx, strings.TrimSpace(in.TenantID), deviceAuthJoinTokenTTL, true)
	if err != nil {
		http.Error(w, "failed to create join token", http.StatusInternalServerError)
		return
	}
	req, err := store.approve(code, strings.TrimSpace(in.TenantID), tenantName, in.AgentName, principal.User.Username, rawToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	logRequestAudit(r, &storage.AuditEntry{
		Action:     "device_auth.approve",
		TargetType: "agent_pending",
		TargetID:   req.Metadata.AgentID,
		TenantID:   req.TenantID,
		Details:    fmt.Sprintf("Approved agent %s via device auth", req.Metadata.AgentID),
		Metadata: map[string]interface{}{
			"code":      req.Code,
			"tenant_id": req.TenantID,
		},
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"status":  req.Status,
	})
}

func handleDeviceAuthReject(w http.ResponseWriter, r *http.Request, store *deviceAuthStore, code string) {
	principal := getPrincipal(r)
	if principal == nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	snapshot, ok := store.snapshot(code)
	if !ok || snapshot == nil {
		http.NotFound(w, r)
		return
	}
	if snapshot.Status != deviceAuthStatusPending {
		http.Error(w, "request not found or already reviewed", http.StatusConflict)
		return
	}
	resource := authz.ResourceRef{}
	if snapshot.TenantID != "" {
		resource.TenantIDs = []string{snapshot.TenantID}
	}
	if !authorizeOrReject(w, r, authz.ActionAgentsWrite, resource) {
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSONBody(r, &in); err != nil && err != io.EOF {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	reason := strings.TrimSpace(in.Reason)
	if len(reason) > deviceAuthMaxReason {
		http.Error(w, "reason too long", http.StatusBadRequest)
		return
	}
	if reason == "" {
		reason = "Rejected by operator"
	}
	req, err := store.reject(code, reason, principal.User.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	logRequestAudit(r, &storage.AuditEntry{
		Action:     "device_auth.reject",
		TargetType: "agent_pending",
		TargetID:   req.Metadata.AgentID,
		TenantID:   req.TenantID,
		Details:    fmt.Sprintf("Rejected agent %s via device auth", req.Metadata.AgentID),
		Metadata: map[string]interface{}{
			"code": req.Code,
		},
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"status":  req.Status,
		"message": req.Message,
	})
}

func handleDeviceAuthPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := ensureInteractiveSession(w, r); !ok {
		return
	}
	code := strings.TrimPrefix(r.URL.Path, "/device-auth/")
	code = strings.Trim(code, "/")
	if code == "" {
		http.NotFound(w, r)
		return
	}
	tmpl, err := template.ParseFS(webFS, "web/device_auth.html")
	if err != nil {
		logError("Failed to parse device auth template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	data := map[string]string{"Code": strings.ToUpper(code)}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		logError("Failed to render device auth template", "error", err)
	}
}
