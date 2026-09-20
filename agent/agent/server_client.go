package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	pmsettings "printmaster/common/settings"
	"printmaster/common/updateauth"
)

// ServerClient handles uploading agent data to the central PrintMaster server
// This is the agent's HTTP client for server communication
type ServerClient struct {
	updateKeys         updateauth.Keyring
	updateKeyError     error
	BaseURL            string
	AgentID            string
	AgentName          string // User-friendly agent name
	Token              string
	identity           *ClientIdentity
	HTTPClient         *http.Client
	InsecureSkipVerify bool
	tlsConfigError     error
	mu                 sync.RWMutex
	lastHeartbeat      time.Time
	lastDeviceUpload   time.Time
	lastMetricsUpload  time.Time
}

// MTLSRegistration is the public portion of a server-issued Agent identity.
// The caller supplies the matching private key from PendingIdentity when
// persisting it locally.
type MTLSRegistration struct {
	CredentialID      string    `json:"credential_id"`
	TenantID          string    `json:"tenant_id"`
	AgentID           string    `json:"agent_id"`
	ClientCertificate []byte    `json:"client_certificate"`
	ExpiresAt         time.Time `json:"expires_at"`
}

const maxServerResponseBytes = 2 << 20

// SettingsSnapshot mirrors the server's managed settings payload.
type SettingsSnapshot struct {
	Version         string              `json:"version"`
	SchemaVersion   string              `json:"schema_version"`
	UpdatedAt       time.Time           `json:"updated_at"`
	ManagedSections []string            `json:"managed_sections"`
	Settings        pmsettings.Settings `json:"settings"`
}

// HeartbeatResult captures metadata returned from a heartbeat call.
type HeartbeatResult struct {
	SettingsVersion string
	Snapshot        *SettingsSnapshot
}

// NewServerClient creates a new server uploader for this agent
// If caCertPath is provided, uses it to validate server certificate (for self-signed certs)
// If caCertPath is empty, uses system CA pool (works with Let's Encrypt)
func NewServerClient(baseURL, agentID, token string) *ServerClient {
	return NewServerClientWithName(baseURL, agentID, "", token, "", false)
}

// NewServerClientWithName creates a new server client with agent name
func NewServerClientWithName(baseURL, agentID, agentName, token, caCertPath string, insecureSkipVerify bool) *ServerClient {
	updateKeys, updateKeyError := updateauth.LoadKeyring(os.Getenv("PRINTMASTER_UPDATE_TRUST_FILE"))
	// Use agent package logger for structured logging when available
	Info(fmt.Sprintf("NewServerClientWithName baseURL=%s insecureSkipVerify=%v caCertPath=%s", baseURL, insecureSkipVerify, caCertPath))
	tlsConfig, tlsConfigError := buildServerTLSConfig(caCertPath, insecureSkipVerify)

	return &ServerClient{
		updateKeys:     updateKeys,
		updateKeyError: updateKeyError,
		BaseURL:        baseURL,
		AgentID:        agentID,
		AgentName:      agentName,
		Token:          token,
		// Never expose a client which silently disables certificate validation.
		InsecureSkipVerify: false,
		tlsConfigError:     tlsConfigError,
		HTTPClient: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: sameOriginRedirect,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}
}

func buildServerTLSConfig(caCertPath string, insecureSkipVerify bool) (*tls.Config, error) {
	if insecureSkipVerify {
		return nil, fmt.Errorf("insecure TLS verification is not permitted")
	}
	if strings.TrimSpace(caCertPath) == "" {
		return &tls.Config{MinVersion: tls.VersionTLS12}, nil
	}
	cleanPath := filepath.Clean(caCertPath)
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid CA certificate path")
	}
	caCert, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("read custom CA certificate: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("custom CA certificate contains no valid PEM certificates")
	}
	return &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12}, nil
}

// NewServerClientWithCA creates a new server client with optional custom CA certificate
func NewServerClientWithCA(baseURL, agentID, token, caCertPath string) *ServerClient {
	return NewServerClientWithName(baseURL, agentID, "", token, caCertPath, false)
}

// NewServerClientWithCAAndSkipVerify creates a new server client with optional custom CA and skip verify option
func NewServerClientWithCAAndSkipVerify(baseURL, agentID, token, caCertPath string, insecureSkipVerify bool) *ServerClient {
	return NewServerClientWithName(baseURL, agentID, "", token, caCertPath, insecureSkipVerify)
}

// IsInsecureSkipVerify returns whether this client was configured to skip TLS verification.
func (c *ServerClient) IsInsecureSkipVerify() bool {
	return false
}

// SetToken updates the authentication token
func (c *ServerClient) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Token = token
}

// GetToken retrieves the current authentication token
func (c *ServerClient) GetToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Token
}

func (c *ServerClient) SetClientIdentity(identity *ClientIdentity) error {
	if identity == nil || len(identity.Certificate.Certificate) == 0 {
		return fmt.Errorf("client identity required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.swapHTTPTransportLocked(&identity.Certificate); err != nil {
		return err
	}
	identityCopy := *identity
	c.identity = &identityCopy
	return nil
}

func (c *ServerClient) GetClientIdentity() *ClientIdentity {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.identity == nil {
		return nil
	}
	copy := *c.identity
	return &copy
}

func (c *ServerClient) HasClientIdentity() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.identity != nil && len(c.identity.Certificate.Certificate) > 0
}

func (c *ServerClient) ClearClientIdentity() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.identity = nil
	_ = c.swapHTTPTransportLocked(nil)
}

// TLSConfig returns a private TLS configuration snapshot for the WebSocket
// client. Callers must never mutate the live HTTP transport configuration.
func (c *ServerClient) TLSConfig() *tls.Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.HTTPClient == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	transport, ok := c.HTTPClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return transport.TLSClientConfig.Clone()
}

// swapHTTPTransportLocked installs a fresh transport/client pair. A
// http.Transport must not have TLSClientConfig mutated after first use: an
// existing keep-alive connection can otherwise continue using the old TLS
// session and concurrent requests race with the mutation. Closing idle
// connections and replacing the transport makes the new identity effective
// for every request started after this method returns.
func (c *ServerClient) swapHTTPTransportLocked(identity *tls.Certificate) error {
	if c.HTTPClient == nil {
		return fmt.Errorf("HTTP client unavailable")
	}
	var oldTransport *http.Transport
	if existing, ok := c.HTTPClient.Transport.(*http.Transport); ok {
		oldTransport = existing
	}
	var nextTransport *http.Transport
	if oldTransport != nil {
		nextTransport = oldTransport.Clone()
	} else if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		nextTransport = defaultTransport.Clone()
	} else {
		nextTransport = &http.Transport{}
	}
	cfg := nextTransport.TLSClientConfig
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		cfg = cfg.Clone()
	}
	if identity == nil {
		cfg.Certificates = nil
	} else {
		cfg.Certificates = []tls.Certificate{*identity}
	}
	nextTransport.TLSClientConfig = cfg
	if oldTransport != nil {
		oldTransport.CloseIdleConnections()
	}
	nextClient := *c.HTTPClient
	nextClient.Transport = nextTransport
	c.HTTPClient = &nextClient
	return nil
}

// withClientIdentitySuppressed runs a bootstrap request without presenting a
// possibly stale client certificate. This is needed when a previously stored
// identity is expired/revoked but a join token or legacy bearer is still
// available for controlled recovery.
func (c *ServerClient) withClientIdentitySuppressed(fn func() error) error {
	previous := c.GetClientIdentity()
	if previous == nil {
		return fn()
	}
	c.ClearClientIdentity()
	defer func() {
		if c.GetClientIdentity() == nil {
			_ = c.SetClientIdentity(previous)
		}
	}()
	return fn()
}

// GetServerURL retrieves the base server URL
func (c *ServerClient) GetServerURL() string {
	return c.BaseURL
}

// Register performs initial agent registration with the server
// Returns the authentication token on success
func (c *ServerClient) Register(ctx context.Context, version string) (string, error) {
	type RegisterRequest struct {
		AgentID         string `json:"agent_id"`
		Name            string `json:"name,omitempty"` // User-friendly name
		AgentVersion    string `json:"agent_version"`
		ProtocolVersion string `json:"protocol_version"`
		Hostname        string `json:"hostname"`
		IP              string `json:"ip"`
		Platform        string `json:"platform"`
		// Additional metadata
		OSVersion     string `json:"os_version,omitempty"`
		GoVersion     string `json:"go_version,omitempty"`
		Architecture  string `json:"architecture,omitempty"`
		NumCPU        int    `json:"num_cpu,omitempty"`
		TotalMemoryMB int64  `json:"total_memory_mb,omitempty"`
		BuildType     string `json:"build_type,omitempty"`
		GitCommit     string `json:"git_commit,omitempty"`
	}

	type RegisterResponse struct {
		Success bool   `json:"success"`
		AgentID string `json:"agent_id"`
		Token   string `json:"token"`
		Message string `json:"message"`
	}

	hostname, _ := getHostname()
	localIP, _ := getLocalIP()

	req := RegisterRequest{
		AgentID:         c.AgentID,
		Name:            c.AgentName, // Use client's agent name
		AgentVersion:    version,
		ProtocolVersion: "1",
		Hostname:        hostname,
		IP:              localIP,
		Platform:        GetPlatformInfo(),
		OSVersion:       GetOSVersionDetailed(),
		GoVersion:       runtime.Version(),
		Architecture:    runtime.GOARCH,
		NumCPU:          runtime.NumCPU(),
		TotalMemoryMB:   getTotalMemoryMB(),
		BuildType:       getBuildType(),
		GitCommit:       getGitCommit(),
	}

	var resp RegisterResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/agents/register", req, &resp, false); err != nil {
		return "", fmt.Errorf("registration failed: %w", err)
	}

	if !resp.Success {
		return "", fmt.Errorf("registration failed: %s", resp.Message)
	}

	// Store token for future requests
	if resp.Token != "" {
		c.SetToken(resp.Token)
	}

	return resp.Token, nil
}

// RegisterWithToken registers the agent using a join token issued by the server.
// On success it returns the agent-scoped token issued by the server and the
// tenant ID the agent was assigned to. The returned agent token is also stored
// on the client instance for future requests.
func (c *ServerClient) RegisterWithToken(ctx context.Context, joinToken string, version string) (string, string, error) {
	type JoinRequest struct {
		Token           string `json:"token"`
		AgentID         string `json:"agent_id"`
		Name            string `json:"name,omitempty"`
		AgentVersion    string `json:"agent_version,omitempty"`
		ProtocolVersion string `json:"protocol_version,omitempty"`
	}

	type JoinResponse struct {
		Success    bool   `json:"success"`
		TenantID   string `json:"tenant_id"`
		AgentToken string `json:"agent_token"`
		Message    string `json:"message,omitempty"`
	}

	hostname, _ := getHostname()

	req := JoinRequest{
		Token:           joinToken,
		AgentID:         c.AgentID,
		Name:            c.AgentName,
		AgentVersion:    version,
		ProtocolVersion: "1",
	}

	var resp JoinResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/agents/register-with-token", req, &resp, false); err != nil {
		return "", "", fmt.Errorf("register-with-token failed: %w", err)
	}

	if !resp.Success {
		return "", "", fmt.Errorf("register-with-token failed: %s", resp.Message)
	}

	// Store token for future authenticated requests
	if resp.AgentToken != "" {
		c.SetToken(resp.AgentToken)
	}

	// If Name wasn't set, and server returned success, ensure we have hostname set
	if c.AgentName == "" {
		c.AgentName = hostname
	}

	return resp.AgentToken, resp.TenantID, nil
}

// RegisterWithMTLS enrolls the Agent using a join token and CSR. It never
// sends or persists the private key; callers must save the returned certificate
// together with the PendingIdentity key before activating it.
func (c *ServerClient) RegisterWithMTLS(ctx context.Context, joinToken, csrPEM, version string) (*MTLSRegistration, error) {
	type joinRequest struct {
		Token           string `json:"token"`
		AgentID         string `json:"agent_id"`
		Name            string `json:"name,omitempty"`
		AgentVersion    string `json:"agent_version,omitempty"`
		ProtocolVersion string `json:"protocol_version,omitempty"`
		CSR             string `json:"csr"`
	}
	var resp MTLSRegistration
	var envelope struct {
		Success           bool      `json:"success"`
		CredentialID      string    `json:"credential_id"`
		TenantID          string    `json:"tenant_id"`
		AgentID           string    `json:"agent_id"`
		ClientCertificate string    `json:"client_certificate"`
		ExpiresAt         time.Time `json:"expires_at"`
		Message           string    `json:"message,omitempty"`
	}
	req := joinRequest{Token: joinToken, AgentID: c.AgentID, Name: c.AgentName, AgentVersion: version, ProtocolVersion: "1", CSR: csrPEM}
	var requestErr error
	requestErr = c.withClientIdentitySuppressed(func() error {
		return c.doRequest(ctx, http.MethodPost, "/api/v1/agents/register-mtls", req, &envelope, false)
	})
	if requestErr != nil {
		return nil, fmt.Errorf("register-mtls failed: %w", requestErr)
	}
	if !envelope.Success || envelope.CredentialID == "" || envelope.ClientCertificate == "" {
		return nil, fmt.Errorf("register-mtls failed: %s", envelope.Message)
	}
	resp.CredentialID, resp.TenantID, resp.AgentID = envelope.CredentialID, envelope.TenantID, envelope.AgentID
	resp.ClientCertificate, resp.ExpiresAt = []byte(envelope.ClientCertificate), envelope.ExpiresAt
	return &resp, nil
}

func (c *ServerClient) MigrateToMTLS(ctx context.Context, csrPEM []byte) (*MTLSRegistration, error) {
	var envelope struct {
		Success           bool      `json:"success"`
		CredentialID      string    `json:"credential_id"`
		TenantID          string    `json:"tenant_id"`
		AgentID           string    `json:"agent_id"`
		ClientCertificate string    `json:"client_certificate"`
		ExpiresAt         time.Time `json:"expires_at"`
	}
	payload := map[string]string{"csr": string(csrPEM)}
	if err := c.withClientIdentitySuppressed(func() error {
		return c.doRequest(ctx, http.MethodPost, "/api/v1/agents/identity/migrate", payload, &envelope, true)
	}); err != nil {
		return nil, fmt.Errorf("mTLS migration failed: %w", err)
	}
	if envelope.CredentialID == "" || envelope.ClientCertificate == "" {
		return nil, fmt.Errorf("mTLS migration returned incomplete identity")
	}
	return &MTLSRegistration{CredentialID: envelope.CredentialID, TenantID: envelope.TenantID, AgentID: envelope.AgentID, ClientCertificate: []byte(envelope.ClientCertificate), ExpiresAt: envelope.ExpiresAt}, nil
}

func (c *ServerClient) RenewMTLS(ctx context.Context, csrPEM []byte) (*MTLSRegistration, error) {
	var envelope struct {
		Success           bool      `json:"success"`
		CredentialID      string    `json:"credential_id"`
		TenantID          string    `json:"tenant_id"`
		AgentID           string    `json:"agent_id"`
		ClientCertificate string    `json:"client_certificate"`
		ExpiresAt         time.Time `json:"expires_at"`
	}
	payload := map[string]string{"csr": string(csrPEM)}
	if err := c.doRequest(ctx, http.MethodPost, "/api/v1/agents/identity/renew", payload, &envelope, true); err != nil {
		return nil, fmt.Errorf("mTLS renewal failed: %w", err)
	}
	if envelope.CredentialID == "" || envelope.ClientCertificate == "" {
		return nil, fmt.Errorf("mTLS renewal returned incomplete identity")
	}
	return &MTLSRegistration{CredentialID: envelope.CredentialID, TenantID: envelope.TenantID, AgentID: envelope.AgentID, ClientCertificate: []byte(envelope.ClientCertificate), ExpiresAt: envelope.ExpiresAt}, nil
}

func (c *ServerClient) ActivateMTLS(ctx context.Context) error {
	var resp struct {
		Success bool `json:"success"`
	}
	if err := c.doRequest(ctx, http.MethodPost, "/api/v1/agents/identity/activate", map[string]bool{}, &resp, true); err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("mTLS activation rejected")
	}
	return nil
}

// DeviceAuthStartRequest captures the metadata sent to the server when initiating
// a device-authorization flow from the agent UI.
type DeviceAuthStartRequest struct {
	AgentID      string `json:"agent_id"`
	AgentName    string `json:"agent_name,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	Platform     string `json:"platform,omitempty"`
}

// DeviceAuthStartResponse mirrors the server payload returned after creating a
// device authorization request.
type DeviceAuthStartResponse struct {
	Success      bool   `json:"success"`
	Code         string `json:"code"`
	PollToken    string `json:"poll_token"`
	ExpiresAt    string `json:"expires_at"`
	AuthorizeURL string `json:"authorize_url"`
	Message      string `json:"message"`
}

// DeviceAuthPollResponse captures the status returned while polling an ongoing
// device authorization exchange.
type DeviceAuthPollResponse struct {
	Success   bool   `json:"success"`
	Status    string `json:"status"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	JoinToken string `json:"join_token,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
}

// DeviceAuthStart begins the login-based onboarding handshake by creating a
// short-lived approval code on the server.
func (c *ServerClient) DeviceAuthStart(ctx context.Context, req DeviceAuthStartRequest) (*DeviceAuthStartResponse, error) {
	var resp DeviceAuthStartResponse
	if err := c.doRequest(ctx, http.MethodPost, "/api/v1/agents/device-auth/start", req, &resp, false); err != nil {
		return nil, fmt.Errorf("device auth start failed: %w", err)
	}
	if !resp.Success {
		if resp.Message != "" {
			return nil, fmt.Errorf("device auth start failed: %s", resp.Message)
		}
		return nil, fmt.Errorf("device auth start failed")
	}
	return &resp, nil
}

// DeviceAuthPoll checks the server for updates about a pending device
// authorization request using the opaque poll token issued during start.
func (c *ServerClient) DeviceAuthPoll(ctx context.Context, pollToken string) (*DeviceAuthPollResponse, error) {
	cleanToken := strings.TrimSpace(pollToken)
	if cleanToken == "" {
		return nil, fmt.Errorf("poll token required")
	}
	var resp DeviceAuthPollResponse
	payload := map[string]string{"poll_token": cleanToken}
	if err := c.doRequest(ctx, http.MethodPost, "/api/v1/agents/device-auth/poll", payload, &resp, false); err != nil {
		return nil, fmt.Errorf("device auth poll failed: %w", err)
	}
	if !resp.Success {
		if resp.Message != "" {
			return nil, fmt.Errorf("device auth poll failed: %s", resp.Message)
		}
		return nil, fmt.Errorf("device auth poll failed")
	}
	return &resp, nil
}

// AgentVersionInfo contains agent version metadata for heartbeat
type AgentVersionInfo struct {
	Version         string
	ProtocolVersion string
	BuildType       string
	GitCommit       string
}

// Heartbeat sends a keep-alive signal to the server and returns any managed settings snapshot metadata.
func (c *ServerClient) Heartbeat(ctx context.Context, settingsVersion string) (*HeartbeatResult, error) {
	return c.HeartbeatWithVersion(ctx, settingsVersion, nil)
}

// HeartbeatWithVersion sends a heartbeat with optional version info to update server-side agent metadata.
func (c *ServerClient) HeartbeatWithVersion(ctx context.Context, settingsVersion string, versionInfo *AgentVersionInfo) (*HeartbeatResult, error) {
	type HeartbeatRequest struct {
		AgentID         string    `json:"agent_id"`
		Timestamp       time.Time `json:"timestamp"`
		Status          string    `json:"status"`
		SettingsVersion string    `json:"settings_version,omitempty"`
		// Version info - sent to keep server DB up to date after agent updates
		Version         string `json:"version,omitempty"`
		ProtocolVersion string `json:"protocol_version,omitempty"`
		Hostname        string `json:"hostname,omitempty"`
		IP              string `json:"ip,omitempty"`
		Platform        string `json:"platform,omitempty"`
		OSVersion       string `json:"os_version,omitempty"`
		GoVersion       string `json:"go_version,omitempty"`
		Architecture    string `json:"architecture,omitempty"`
		BuildType       string `json:"build_type,omitempty"`
		GitCommit       string `json:"git_commit,omitempty"`
	}

	type HeartbeatResponse struct {
		Success          bool              `json:"success"`
		SettingsVersion  string            `json:"settings_version,omitempty"`
		SettingsSnapshot *SettingsSnapshot `json:"settings_snapshot,omitempty"`
	}

	hostname, _ := os.Hostname()

	req := HeartbeatRequest{
		AgentID:         c.AgentID,
		Timestamp:       time.Now(),
		Status:          "active",
		SettingsVersion: settingsVersion,
		Hostname:        hostname,
		Platform:        runtime.GOOS,
		Architecture:    runtime.GOARCH,
		GoVersion:       runtime.Version(),
	}

	// Include version info if provided
	if versionInfo != nil {
		req.Version = versionInfo.Version
		req.ProtocolVersion = versionInfo.ProtocolVersion
		req.BuildType = versionInfo.BuildType
		req.GitCommit = versionInfo.GitCommit
	}

	var resp HeartbeatResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/agents/heartbeat", req, &resp, true); err != nil {
		return nil, fmt.Errorf("heartbeat failed: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("heartbeat failed")
	}

	c.mu.Lock()
	c.lastHeartbeat = time.Now()
	c.mu.Unlock()

	return &HeartbeatResult{
		SettingsVersion: resp.SettingsVersion,
		Snapshot:        resp.SettingsSnapshot,
	}, nil
}

// UploadDevices sends discovered devices to the server
func (c *ServerClient) UploadDevices(ctx context.Context, devices []interface{}) error {
	type DevicesBatchRequest struct {
		AgentID   string        `json:"agent_id"`
		Timestamp time.Time     `json:"timestamp"`
		Devices   []interface{} `json:"devices"`
	}

	req := DevicesBatchRequest{
		AgentID:   c.AgentID,
		Timestamp: time.Now(),
		Devices:   devices,
	}

	var resp map[string]interface{}
	if err := c.doRequest(ctx, "POST", "/api/v1/devices/batch", req, &resp, true); err != nil {
		return fmt.Errorf("device upload failed: %w", err)
	}

	c.mu.Lock()
	c.lastDeviceUpload = time.Now()
	c.mu.Unlock()

	return nil
}

// UploadMetrics sends device metrics to the server
func (c *ServerClient) UploadMetrics(ctx context.Context, metrics []interface{}) error {
	type MetricsBatchRequest struct {
		AgentID   string        `json:"agent_id"`
		Timestamp time.Time     `json:"timestamp"`
		Metrics   []interface{} `json:"metrics"`
	}

	req := MetricsBatchRequest{
		AgentID:   c.AgentID,
		Timestamp: time.Now(),
		Metrics:   metrics,
	}

	var resp map[string]interface{}
	if err := c.doRequest(ctx, "POST", "/api/v1/metrics/batch", req, &resp, true); err != nil {
		return fmt.Errorf("metrics upload failed: %w", err)
	}

	c.mu.Lock()
	c.lastMetricsUpload = time.Now()
	c.mu.Unlock()

	return nil
}

// LogAuditEvent sends an audit log entry to the server
func (c *ServerClient) LogAuditEvent(ctx context.Context, action, resourceType, resourceID string, details map[string]interface{}) error {
	type AuditRequest struct {
		AgentID      string                 `json:"agent_id"`
		Timestamp    time.Time              `json:"timestamp"`
		Action       string                 `json:"action"`
		ResourceType string                 `json:"resource_type"`
		ResourceID   string                 `json:"resource_id"`
		Details      map[string]interface{} `json:"details"`
	}

	req := AuditRequest{
		AgentID:      c.AgentID,
		Timestamp:    time.Now(),
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
	}

	var resp map[string]interface{}
	if err := c.doRequest(ctx, "POST", "/api/v1/audit/log", req, &resp, true); err != nil {
		// Don't fail the operation if audit logging fails, just log it
		return fmt.Errorf("audit log failed: %w", err)
	}

	return nil
}

// DeviceCredentials holds web UI credentials for auto-login
type DeviceCredentials struct {
	Exists    bool   `json:"exists"`
	Username  string `json:"username"`
	Password  string `json:"password"` // plaintext (decrypted by server)
	AuthType  string `json:"auth_type"`
	AutoLogin bool   `json:"auto_login"`
	Error     string `json:"error,omitempty"`
}

// GetDeviceCredentials fetches device web UI credentials from the server.
// Returns nil if credentials are not found or an error occurs.
func (c *ServerClient) GetDeviceCredentials(ctx context.Context, serial string) (*DeviceCredentials, error) {
	if serial == "" {
		return nil, fmt.Errorf("serial required")
	}

	var resp DeviceCredentials
	path := "/api/v1/agents/device-credentials?serial=" + url.QueryEscape(serial)
	if err := c.doRequest(ctx, "GET", path, nil, &resp, true); err != nil {
		return nil, err
	}

	if !resp.Exists {
		return nil, fmt.Errorf("credentials not found")
	}

	return &resp, nil
}

// GetStats returns client statistics
func (c *ServerClient) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"last_heartbeat":      c.lastHeartbeat,
		"last_device_upload":  c.lastDeviceUpload,
		"last_metrics_upload": c.lastMetricsUpload,
		"has_token":           c.Token != "",
	}
}

// doRequest performs an HTTP request with optional authentication
func (c *ServerClient) doRequest(ctx context.Context, method, path string, reqBody, respBody interface{}, requireAuth bool) error {
	if c.tlsConfigError != nil {
		return fmt.Errorf("server TLS configuration rejected: %w", c.tlsConfigError)
	}
	url := c.BaseURL + path

	// Encode request body
	var bodyReader io.Reader
	if reqBody != nil {
		jsonData, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed to encode request: %w", err)
		}
		bodyReader = bytes.NewReader(jsonData)
	}

	// Create request
	httpReq, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "PrintMaster-Agent/1.0")

	// mTLS is the primary authentication transport when a client identity has
	// been installed. Bearer is retained only for the migration fallback.
	if requireAuth {
		if !c.HasClientIdentity() && c.GetToken() == "" {
			return fmt.Errorf("authentication required but no token available")
		}
		if !c.HasClientIdentity() {
			httpReq.Header.Set("Authorization", "Bearer "+c.GetToken())
		}
	}

	// Perform request (log for debugging)
	tokenPresent := false
	if requireAuth {
		token := c.GetToken()
		tokenPresent = token != ""
	}
	Debug(fmt.Sprintf("HTTP request: method=%s url=%s requireAuth=%v tokenPresent=%v mtls=%v", method, url, requireAuth, tokenPresent, c.HasClientIdentity()))

	// Perform request
	c.mu.RLock()
	httpClient := c.HTTPClient
	c.mu.RUnlock()
	if httpClient == nil {
		return fmt.Errorf("HTTP client unavailable")
	}
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		Error(fmt.Sprintf("HTTP request failed: %v", err))
		return fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	// Read response body with a hard cap. Server responses are JSON control
	// messages; an unexpectedly large response must not exhaust the agent.
	respData, err := io.ReadAll(io.LimitReader(httpResp.Body, maxServerResponseBytes+1))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	if len(respData) > maxServerResponseBytes {
		return fmt.Errorf("server response exceeds %d bytes", maxServerResponseBytes)
	}

	// Check status code
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		Error(fmt.Sprintf("Server returned non-2xx status %d for %s %s: %s", httpResp.StatusCode, method, url, string(respData)))
		return fmt.Errorf("server returned status %d: %s", httpResp.StatusCode, string(respData))
	}

	// Decode response if needed
	if respBody != nil {
		if err := json.Unmarshal(respData, respBody); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// Helper functions

func getHostname() (string, error) {
	// Try to import os package
	hostname, err := getHostnameInternal()
	if err != nil || hostname == "" {
		return "unknown", err
	}
	return hostname, nil
}

func getLocalIP() (string, error) {
	// Try to get local IP
	ip, err := getLocalIPInternal()
	if err != nil || ip == "" {
		return "unknown", err
	}
	return ip, nil
}

// These will be implemented in helpers.go or can be simple stubs
var getHostnameInternal = func() (string, error) {
	// Implementation will use os.Hostname()
	return "agent-host", nil
}

var getLocalIPInternal = func() (string, error) {
	// Implementation will use net.InterfaceAddrs()
	return "192.168.1.100", nil
}

// getTotalMemoryMB returns the total system memory in MB
func getTotalMemoryMB() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// This returns allocated memory, not total system memory
	// For actual total system memory, would need platform-specific syscalls
	return int64(m.Sys / 1024 / 1024)
}

// These variables will be set at build time via -ldflags
var (
	buildType = "dev"
	gitCommit = "unknown"
)

// getBuildType returns the build type (dev or release)
func getBuildType() string {
	return buildType
}

// getGitCommit returns the git commit hash
func getGitCommit() string {
	return gitCommit
}

// UpdateManifest represents a signed manifest for an available update.
type UpdateManifest = updateauth.Manifest

// GetLatestManifest fetches the latest update manifest from the server.
func (c *ServerClient) GetLatestManifest(ctx context.Context, component, platform, arch, channel string) (*UpdateManifest, error) {
	type ManifestRequest struct {
		AgentID   string `json:"agent_id"`
		Component string `json:"component"`
		Platform  string `json:"platform"`
		Arch      string `json:"arch"`
		Channel   string `json:"channel"`
	}

	type ManifestResponse struct {
		Success  bool            `json:"success"`
		Manifest *UpdateManifest `json:"manifest,omitempty"`
		Message  string          `json:"message,omitempty"`
	}

	req := ManifestRequest{
		AgentID:   c.AgentID,
		Component: component,
		Platform:  platform,
		Arch:      arch,
		Channel:   channel,
	}

	var resp ManifestResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/agents/update/manifest", req, &resp, true); err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}

	if !resp.Success {
		if resp.Message != "" {
			return nil, fmt.Errorf("manifest request failed: %s", resp.Message)
		}
		return nil, fmt.Errorf("manifest request failed")
	}

	if resp.Manifest == nil {
		return nil, fmt.Errorf("no manifest returned")
	}
	if c.updateKeyError != nil {
		return nil, fmt.Errorf("update trust configuration: %w", c.updateKeyError)
	}
	if err := c.updateKeys.Verify(resp.Manifest, updateauth.Target{Component: component, Platform: platform, Arch: arch, Channel: channel}, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("untrusted update manifest: %w", err)
	}

	return resp.Manifest, nil
}

// DownloadArtifact downloads an update artifact to the specified path.
// Supports resuming partial downloads via HTTP Range requests.
// Returns the total bytes downloaded (including resumed bytes).
func (c *ServerClient) DownloadArtifact(ctx context.Context, manifest *UpdateManifest, destPath string, resumeFrom int64) (int64, error) {
	return c.DownloadArtifactWithProgress(ctx, manifest, destPath, resumeFrom, nil)
}

// DownloadArtifactWithProgress downloads an artifact with optional progress reporting.
// The callback receives progress percentage (0-100) and total bytes read.
func (c *ServerClient) DownloadArtifactWithProgress(ctx context.Context, manifest *UpdateManifest, destPath string, resumeFrom int64, progressCb DownloadProgressCallback) (int64, error) {
	if manifest == nil {
		return 0, fmt.Errorf("manifest required")
	}
	if c.tlsConfigError != nil {
		return 0, fmt.Errorf("server TLS configuration rejected: %w", c.tlsConfigError)
	}
	if c.updateKeyError != nil {
		return 0, fmt.Errorf("update trust configuration: %w", c.updateKeyError)
	}
	if err := c.updateKeys.Verify(manifest, updateauth.Target{Component: "agent", Platform: runtime.GOOS, Arch: runtime.GOARCH, Channel: manifest.Channel}, time.Now().UTC()); err != nil {
		return 0, err
	}
	if resumeFrom < 0 || resumeFrom > manifest.SizeBytes {
		return 0, fmt.Errorf("invalid resume offset")
	}

	downloadURL := manifest.DownloadURL
	if downloadURL == "" {
		// Construct URL from base + version
		downloadURL = fmt.Sprintf("%s/api/v1/agents/update/download/%s/%s/%s",
			c.BaseURL, manifest.Component, manifest.Version, manifest.Platform+"-"+manifest.Arch)
	} else if strings.HasPrefix(downloadURL, "/") {
		// Server returned a relative URL - prepend the base URL
		downloadURL = strings.TrimSuffix(c.BaseURL, "/") + downloadURL
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil || req.URL.User != nil || req.URL.Scheme != base.Scheme || !strings.EqualFold(req.URL.Host, base.Host) {
		return 0, fmt.Errorf("update download must use the enrolled server origin")
	}

	// Add authorization
	c.mu.RLock()
	token := c.Token
	c.mu.RUnlock()
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Add range header for resume
	if resumeFrom > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", resumeFrom))
	}

	c.mu.RLock()
	httpClient := c.HTTPClient
	c.mu.RUnlock()
	if httpClient == nil {
		return 0, fmt.Errorf("HTTP client unavailable")
	}
	downloadClient := *httpClient
	downloadClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return fmt.Errorf("update download redirects are disabled")
	}
	resp, err := downloadClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Open destination file
	flags := os.O_CREATE | os.O_WRONLY
	if resumeFrom > 0 && resp.StatusCode == http.StatusPartialContent {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
		resumeFrom = 0 // Server didn't support range, start fresh
	}

	file, err := os.OpenFile(destPath, flags, 0o644)
	if err != nil {
		return 0, fmt.Errorf("failed to open destination file: %w", err)
	}
	defer file.Close()

	// Use progress reader if callback is provided and we know the total size
	totalSize := manifest.SizeBytes
	if resumeFrom > 0 && resp.StatusCode == http.StatusPartialContent {
		// For resumed downloads, remaining size is total - already downloaded
		totalSize = manifest.SizeBytes - resumeFrom
	}
	var reader io.Reader = io.LimitReader(resp.Body, totalSize+1)
	if progressCb != nil && totalSize > 0 {
		reader = newProgressReader(reader, totalSize, progressCb)
	}

	written, err := io.Copy(file, reader)
	if err != nil {
		return resumeFrom + written, fmt.Errorf("download interrupted: %w", err)
	}
	if err := file.Close(); err != nil {
		return resumeFrom + written, err
	}
	if err := updateauth.VerifyFile(destPath, manifest); err != nil {
		return resumeFrom + written, err
	}

	return resumeFrom + written, nil
}

// ReportUpdateStatus sends telemetry about an update operation to the server.
func (c *ServerClient) ReportUpdateStatus(ctx context.Context, status, runID, currentVersion, targetVersion string, errCode, errMsg string, metadata map[string]interface{}) error {
	type TelemetryRequest struct {
		AgentID        string                 `json:"agent_id"`
		RunID          string                 `json:"run_id,omitempty"`
		Status         string                 `json:"status"`
		CurrentVersion string                 `json:"current_version"`
		TargetVersion  string                 `json:"target_version,omitempty"`
		ErrorCode      string                 `json:"error_code,omitempty"`
		ErrorMessage   string                 `json:"error_message,omitempty"`
		Timestamp      time.Time              `json:"timestamp"`
		Metadata       map[string]interface{} `json:"metadata,omitempty"`
	}

	req := TelemetryRequest{
		AgentID:        c.AgentID,
		RunID:          runID,
		Status:         status,
		CurrentVersion: currentVersion,
		TargetVersion:  targetVersion,
		ErrorCode:      errCode,
		ErrorMessage:   errMsg,
		Timestamp:      time.Now(),
		Metadata:       metadata,
	}

	var resp map[string]interface{}
	if err := c.doRequest(ctx, "POST", "/api/v1/agents/update/telemetry", req, &resp, true); err != nil {
		return fmt.Errorf("telemetry report failed: %w", err)
	}

	return nil
}
