package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"printmaster/agent/agent"
	"printmaster/agent/storage"
	commonconfig "printmaster/common/config"
)

// Logger interface for upload worker operations
type Logger interface {
	Error(msg string, context ...interface{})
	Warn(msg string, context ...interface{})
	Info(msg string, context ...interface{})
	Debug(msg string, context ...interface{})
}

// UploadWorker handles periodic uploads of device and metrics data to the server
type UploadWorker struct {
	client   *agent.ServerClient
	store    storage.DeviceStore
	settings *SettingsManager
	logger   Logger
	dataDir  string

	// Version info to include in heartbeats
	versionInfo *agent.AgentVersionInfo

	// WebSocket client (optional, falls back to HTTP if unavailable)
	wsClient     *agent.WSClient
	useWebSocket bool
	wsClientMu   sync.RWMutex

	// Local handler for proxy requests (stored here until wsClient is created)
	pendingLocalHandler   http.Handler
	pendingLocalHandlerMu sync.RWMutex

	// Configuration
	heartbeatInterval time.Duration
	uploadInterval    time.Duration
	retryAttempts     int
	retryBackoff      time.Duration

	// State tracking
	mu                sync.RWMutex
	lastHeartbeat     time.Time
	lastDeviceUpload  time.Time
	lastMetricsUpload time.Time
	running           bool

	// Lifecycle
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// UploadWorkerStatus surfaces internal worker timings for diagnostics.
type UploadWorkerStatus struct {
	Running            bool      `json:"running"`
	LastHeartbeat      time.Time `json:"last_heartbeat"`
	LastDeviceUpload   time.Time `json:"last_device_upload"`
	LastMetricsUpload  time.Time `json:"last_metrics_upload"`
	WebSocketEnabled   bool      `json:"websocket_enabled"`
	WebSocketConnected bool      `json:"websocket_connected"`
}

// Status returns snapshot information about the worker lifecycle and recent activity.
func (w *UploadWorker) Status() UploadWorkerStatus {
	if w == nil {
		return UploadWorkerStatus{}
	}
	w.mu.RLock()
	status := UploadWorkerStatus{
		Running:           w.running,
		LastHeartbeat:     w.lastHeartbeat,
		LastDeviceUpload:  w.lastDeviceUpload,
		LastMetricsUpload: w.lastMetricsUpload,
		WebSocketEnabled:  w.useWebSocket,
	}
	w.mu.RUnlock()
	w.wsClientMu.RLock()
	wsClient := w.wsClient
	w.wsClientMu.RUnlock()
	if wsClient != nil && wsClient.IsConnected() {
		status.WebSocketConnected = true
	}
	return status
}

// Client returns the underlying ServerClient for reuse by other subsystems.
func (w *UploadWorker) Client() *agent.ServerClient {
	if w == nil {
		return nil
	}
	return w.client
}

// WSClient returns the underlying WebSocket client for reuse by other subsystems.
func (w *UploadWorker) WSClient() *agent.WSClient {
	if w == nil {
		return nil
	}
	w.wsClientMu.RLock()
	defer w.wsClientMu.RUnlock()
	return w.wsClient
}

// SetLocalHandler sets the local HTTP handler for direct proxy invocation.
// When proxy requests target localhost, the handler is invoked directly
// instead of making an HTTP round-trip.
func (w *UploadWorker) SetLocalHandler(handler http.Handler) {
	if w == nil {
		return
	}

	// Store the handler for later use (in case wsClient doesn't exist yet)
	w.pendingLocalHandlerMu.Lock()
	w.pendingLocalHandler = handler
	w.pendingLocalHandlerMu.Unlock()

	// Apply immediately if wsClient exists
	w.wsClientMu.RLock()
	wsClient := w.wsClient
	w.wsClientMu.RUnlock()
	if wsClient != nil {
		wsClient.SetLocalHandler(handler)
	}
}

func (w *UploadWorker) currentSettingsVersion() string {
	if w.settings == nil {
		return ""
	}
	return w.settings.CurrentVersion()
}

func (w *UploadWorker) handleHeartbeatSettings(result *agent.HeartbeatResult) {
	if result == nil || result.Snapshot == nil || w.settings == nil {
		return
	}
	newVersion := strings.TrimSpace(result.Snapshot.Version)
	if newVersion == "" || newVersion == w.settings.CurrentVersion() {
		return
	}
	effective, err := w.settings.ApplyServerSnapshot(result.Snapshot)
	if err != nil {
		w.logger.Warn("Failed to persist server settings", "error", err)
		return
	}
	applyEffectiveSettingsSnapshot(effective)
}

// ReloadSettings requests the current managed settings immediately.
// HTTP is used because WebSocket heartbeats are fire-and-forget.
func (w *UploadWorker) ReloadSettings(ctx context.Context) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("upload worker unavailable")
	}
	result, err := w.client.HeartbeatWithVersion(ctx, w.currentSettingsVersion(), w.versionInfo)
	if err != nil {
		return err
	}
	w.handleHeartbeatSettings(result)
	return nil
}

// UploadWorkerConfig contains configuration for the upload worker
type UploadWorkerConfig struct {
	HeartbeatInterval time.Duration
	UploadInterval    time.Duration
	RetryAttempts     int
	RetryBackoff      time.Duration
	UseWebSocket      bool // Enable WebSocket for heartbeats
}

// NewUploadWorker creates a new upload worker instance
func NewUploadWorker(client *agent.ServerClient, store storage.DeviceStore, logger Logger, settings *SettingsManager, config UploadWorkerConfig, dataDir string) *UploadWorker {
	// Apply defaults
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 60 * time.Second
	}
	if config.UploadInterval == 0 {
		config.UploadInterval = 300 * time.Second
	}
	if config.RetryAttempts == 0 {
		config.RetryAttempts = 3
	}
	if config.RetryBackoff == 0 {
		config.RetryBackoff = 2 * time.Second
	}

	w := &UploadWorker{
		client:            client,
		store:             store,
		settings:          settings,
		logger:            logger,
		dataDir:           dataDir,
		heartbeatInterval: config.HeartbeatInterval,
		uploadInterval:    config.UploadInterval,
		retryAttempts:     config.RetryAttempts,
		retryBackoff:      config.RetryBackoff,
		useWebSocket:      config.UseWebSocket,
		stopCh:            make(chan struct{}),
	}

	return w
}

// Start begins the upload worker goroutines
func (w *UploadWorker) Start(ctx context.Context, version string) error {
	return w.StartWithVersionInfo(ctx, version, nil)
}

// StartWithVersionInfo begins the upload worker with full version metadata
func (w *UploadWorker) StartWithVersionInfo(ctx context.Context, version string, versionInfo *agent.AgentVersionInfo) error {
	// Store version info for heartbeats
	w.versionInfo = versionInfo

	// Ensure agent is registered first
	if err := w.ensureRegistered(ctx, version); err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// Initialize WebSocket client if enabled
	if w.useWebSocket {
		serverURL := w.client.GetServerURL()
		token := w.client.GetToken()

		w.wsClientMu.Lock()
		w.wsClient = agent.NewWSClient(serverURL, token, w.client.IsInsecureSkipVerify())
		w.wsClient.SetTLSConfig(w.client.TLSConfig())
		w.wsClientMu.Unlock()

		// Apply pending local handler if one was set before wsClient existed
		w.pendingLocalHandlerMu.RLock()
		pendingHandler := w.pendingLocalHandler
		w.pendingLocalHandlerMu.RUnlock()
		if pendingHandler != nil {
			w.wsClient.SetLocalHandler(pendingHandler)
		}

		// Start WebSocket client (non-blocking, handles reconnection internally)
		if err := w.wsClient.Start(); err != nil {
			w.logger.Warn("WebSocket client failed to start (falling back to HTTP)", "error", err)
			w.wsClientMu.Lock()
			w.wsClient = nil
			w.wsClientMu.Unlock()
		} else {
			w.logger.Info("WebSocket client started for live heartbeat")
		}
	}

	// Start heartbeat goroutine
	w.wg.Add(1)
	go w.heartbeatLoop()

	// Start upload goroutine
	w.wg.Add(1)
	go w.uploadLoop()

	w.mu.Lock()
	w.running = true
	w.mu.Unlock()

	w.logger.Info("Upload worker started",
		"heartbeat_interval", w.heartbeatInterval,
		"upload_interval", w.uploadInterval,
		"websocket_enabled", w.useWebSocket)

	return nil
}

// Stop gracefully shuts down the upload worker
func (w *UploadWorker) Stop() {
	w.logger.Info("Stopping upload worker...")
	close(w.stopCh)

	// Stop WebSocket client if running
	w.wsClientMu.Lock()
	if w.wsClient != nil {
		w.wsClient.Stop()
		w.wsClient = nil
	}
	w.wsClientMu.Unlock()

	w.wg.Wait()
	w.mu.Lock()
	w.running = false
	w.mu.Unlock()
	w.logger.Info("Upload worker stopped")
}

// ensureRegistered checks if agent has a token, registers if not
func (w *UploadWorker) ensureRegistered(ctx context.Context, version string) error {
	// A certificate may have been issued and activation may have completed on
	// the server while the response was lost. Always retry a persisted pending
	// identity before consuming another join token or falling back to bearer.
	if pending, pendingErr := agent.LoadPendingClientIdentity(w.dataDir); pendingErr != nil {
		return fmt.Errorf("load pending Agent identity: %w", pendingErr)
	} else if pending != nil {
		if activated, activateErr := w.activatePendingMTLS(ctx, pending); !activated {
			return fmt.Errorf("pending mTLS activation requires retry: %w", activateErr)
		}
		return nil
	}
	token := w.client.GetToken()

	if w.client.HasClientIdentity() {
		hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, heartbeatErr := w.client.Heartbeat(hbCtx, w.currentSettingsVersion())
		cancel()
		if heartbeatErr == nil {
			if identity := w.client.GetClientIdentity(); identity != nil && time.Until(identity.ExpiresAt) < 14*24*time.Hour {
				if err := w.renewMTLS(ctx); err != nil {
					w.logger.Warn("Agent mTLS renewal failed; current certificate remains in use", "error", err)
				}
			}
			return nil
		}
		w.logger.Warn("Stored Agent mTLS identity was rejected", "error", heartbeatErr)
	}

	if token != "" {
		// Already have token, validate it with a heartbeat
		hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if _, err := w.client.Heartbeat(hbCtx, w.currentSettingsVersion()); err == nil {
			if migrated, migrateErr := w.migrateMTLS(ctx); migrated {
				return nil
			} else if migrateErr != nil {
				if pending, pendingErr := agent.LoadPendingClientIdentity(w.dataDir); pendingErr != nil {
					return fmt.Errorf("load pending Agent identity after migration: %w", pendingErr)
				} else if pending != nil {
					return fmt.Errorf("mTLS migration is awaiting activation: %w", migrateErr)
				}
				w.logger.Debug("Agent mTLS migration not available; retaining legacy bearer", "error", migrateErr)
			}
			w.logger.Info("Using existing authentication token")
			return nil // Token is valid
		}

		// Token invalid, need to re-register
		w.logger.Warn("Existing token invalid, re-registering")
		w.client.SetToken("")
	}

	joinToken := ""

	// First, try INIT_SECRET for auto-join (Docker Compose scenario)
	initSecret := os.Getenv("INIT_SECRET")
	if initSecret == "" {
		// Common typo safeguard so users with INIT_SERCRET still get auto-join
		initSecret = os.Getenv("INIT_SERCRET")
	}
	if initSecret != "" {
		if err := commonconfig.ValidateInitSecret(initSecret); err != nil {
			return fmt.Errorf("configured INIT_SECRET rejected: %w", err)
		}
		secretUsedFile := filepath.Join(w.dataDir, ".init_secret_used")
		usedBefore := false
		if _, err := os.Stat(secretUsedFile); err == nil {
			usedBefore = true
		}

		if usedBefore {
			w.logger.Info("INIT_SECRET was previously used; retrying because no valid server token is present")
		} else {
			w.logger.Info("Attempting auto-registration with INIT_SECRET")
		}

		joinToken = initSecret

		// Try registration with init secret
		regCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if tenantID, mtlsErr := w.enrollMTLS(regCtx, joinToken, version); mtlsErr == nil {
			cancel()
			if err := os.WriteFile(secretUsedFile, []byte(time.Now().UTC().Format(time.RFC3339)), 0600); err != nil {
				w.logger.Warn("Failed to mark init secret as used", "error", err)
			}
			w.logger.Info("Agent enrolled with mTLS using INIT_SECRET", "tenant_id", tenantID)
			return nil
		} else if pending, pendingErr := agent.LoadPendingClientIdentity(w.dataDir); pendingErr != nil {
			cancel()
			return fmt.Errorf("load pending Agent identity after enrollment: %w", pendingErr)
		} else if pending != nil {
			cancel()
			return fmt.Errorf("mTLS enrollment is awaiting activation: %w", mtlsErr)
		} else if attempt, attemptErr := agent.LoadEnrollmentAttempt(w.dataDir, w.client.AgentID); attemptErr != nil {
			cancel()
			return fmt.Errorf("load pre-enrollment attempt after enrollment: %w", attemptErr)
		} else if attempt != nil {
			cancel()
			return fmt.Errorf("mTLS enrollment will be retried with the persisted attempt: %w", mtlsErr)
		}
		agentToken, tenantID, err := w.client.RegisterWithToken(regCtx, joinToken, version)
		cancel()

		if err == nil && agentToken != "" {
			// Success! Mark init secret as used (idempotent)
			if err := os.WriteFile(secretUsedFile, []byte(time.Now().UTC().Format(time.RFC3339)), 0600); err != nil {
				w.logger.Warn("Failed to mark init secret as used", "error", err)
			}

			if w.dataDir != "" {
				if err := SaveServerToken(w.dataDir, agentToken); err != nil {
					w.logger.Warn("Failed to persist agent token", "error", err)
				}
			}

			masked := agentToken
			if len(masked) > 8 {
				masked = agentToken[:8] + "..."
			}

			w.logger.Info("Agent auto-registered successfully using INIT_SECRET", "token", masked, "tenant_id", tenantID)
			return nil
		}

		w.logger.Warn("Auto-registration with INIT_SECRET failed, falling back to join token", "error", err)
	}

	// Fallback: load join token from file
	if w.dataDir != "" {
		joinToken = LoadServerJoinToken(w.dataDir)
	}

	if joinToken == "" {
		return fmt.Errorf("no join token found; re-run agent onboarding to provision a new join token")
	}

	w.logger.Info("Registering agent with server using join token")
	regCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	if tenantID, mtlsErr := w.enrollMTLS(regCtx, joinToken, version); mtlsErr == nil {
		cancel()
		w.logger.Info("Agent enrolled with mTLS", "tenant_id", tenantID)
		return nil
	} else if pending, pendingErr := agent.LoadPendingClientIdentity(w.dataDir); pendingErr != nil {
		cancel()
		return fmt.Errorf("load pending Agent identity after enrollment: %w", pendingErr)
	} else if pending != nil {
		cancel()
		return fmt.Errorf("mTLS enrollment is awaiting activation: %w", mtlsErr)
	} else if attempt, attemptErr := agent.LoadEnrollmentAttempt(w.dataDir, w.client.AgentID); attemptErr != nil {
		cancel()
		return fmt.Errorf("load pre-enrollment attempt after enrollment: %w", attemptErr)
	} else if attempt != nil {
		cancel()
		return fmt.Errorf("mTLS enrollment will be retried with the persisted attempt: %w", mtlsErr)
	}
	defer cancel()

	agentToken, tenantID, err := w.client.RegisterWithToken(regCtx, joinToken, version)
	if err != nil {
		return fmt.Errorf("register-with-token failed: %w", err)
	}

	if w.dataDir != "" && agentToken != "" {
		if err := SaveServerToken(w.dataDir, agentToken); err != nil {
			w.logger.Warn("Failed to persist agent token", "error", err)
		}
	}

	masked := agentToken
	if len(masked) > 8 {
		masked = agentToken[:8] + "..."
	}

	w.logger.Info("Agent registered successfully", "token", masked, "tenant_id", tenantID)
	return nil
}

func (w *UploadWorker) enrollMTLS(ctx context.Context, joinToken, version string) (string, error) {
	pending, err := agent.LoadOrCreateEnrollmentAttempt(w.dataDir, w.client.AgentID)
	if err != nil {
		return "", err
	}
	registration, err := w.client.RegisterWithMTLS(ctx, joinToken, string(pending.CSRPEM), version, pending.EnrollmentAttemptID)
	if err != nil {
		return "", err
	}
	identity, err := agent.BuildClientIdentity(registration.CredentialID, registration.ExpiresAt, registration.ClientCertificate, pending.PrivateKeyPEM)
	if err != nil {
		return "", err
	}
	identity.TenantID = registration.TenantID
	if err := agent.SavePendingClientIdentity(w.dataDir, identity, registration.ClientCertificate, pending.PrivateKeyPEM); err != nil {
		return "", err
	}
	if activated, err := w.activatePendingMTLS(ctx, identity, pending.EnrollmentAttemptID); !activated {
		return "", err
	}
	return registration.TenantID, nil
}

func (w *UploadWorker) migrateMTLS(ctx context.Context) (bool, error) {
	pending, err := agent.GenerateClientCSR(w.client.AgentID)
	if err != nil {
		return false, err
	}
	registration, err := w.client.MigrateToMTLS(ctx, pending.CSRPEM)
	if err != nil {
		return false, err
	}
	identity, err := agent.BuildClientIdentity(registration.CredentialID, registration.ExpiresAt, registration.ClientCertificate, pending.PrivateKeyPEM)
	if err != nil {
		return false, err
	}
	identity.TenantID = registration.TenantID
	if err := agent.SavePendingClientIdentity(w.dataDir, identity, registration.ClientCertificate, pending.PrivateKeyPEM); err != nil {
		return false, err
	}
	if activated, err := w.activatePendingMTLS(ctx, identity); !activated {
		return false, err
	}
	return true, nil
}

func (w *UploadWorker) renewMTLS(ctx context.Context) error {
	pending, err := agent.GenerateClientCSR(w.client.AgentID)
	if err != nil {
		return err
	}
	registration, err := w.client.RenewMTLS(ctx, pending.CSRPEM)
	if err != nil {
		return err
	}
	identity, err := agent.BuildClientIdentity(registration.CredentialID, registration.ExpiresAt, registration.ClientCertificate, pending.PrivateKeyPEM)
	if err != nil {
		return err
	}
	identity.TenantID = registration.TenantID
	if err := agent.SavePendingClientIdentity(w.dataDir, identity, registration.ClientCertificate, pending.PrivateKeyPEM); err != nil {
		return err
	}
	if activated, err := w.activatePendingMTLS(ctx, identity); !activated {
		return err
	}
	return nil
}

// activatePendingMTLS installs a persisted pending identity, retries the
// idempotent server activation, and promotes the identity only after the
// server confirms success. On failure the previous in-memory identity is
// restored, while the pending files remain for a later retry.
func (w *UploadWorker) activatePendingMTLS(ctx context.Context, pending *agent.ClientIdentity, enrollmentAttemptID ...string) (bool, error) {
	if pending == nil {
		return false, fmt.Errorf("pending Agent identity required")
	}
	previous := w.client.GetClientIdentity()
	if err := w.client.SetClientIdentity(pending); err != nil {
		return false, err
	}
	w.syncWebSocketTLSConfig()
	if err := w.client.ActivateMTLS(ctx); err != nil {
		if previous != nil {
			_ = w.client.SetClientIdentity(previous)
		} else {
			w.client.ClearClientIdentity()
		}
		w.syncWebSocketTLSConfig()
		return false, err
	}
	if err := agent.PromotePendingClientIdentity(w.dataDir); err != nil {
		// The server may already have revoked the old credential. Keep the new
		// in-memory identity and the pending files so promotion can be retried.
		return false, fmt.Errorf("promote activated Agent identity: %w", err)
	}
	attemptID := ""
	if len(enrollmentAttemptID) > 0 {
		attemptID = strings.TrimSpace(enrollmentAttemptID[0])
	}
	if attemptID == "" {
		if attempt, attemptErr := agent.LoadEnrollmentAttempt(w.dataDir, w.client.AgentID); attemptErr != nil {
			return false, fmt.Errorf("load completed enrollment attempt: %w", attemptErr)
		} else if attempt != nil {
			attemptID = attempt.EnrollmentAttemptID
		}
	}
	if attemptID != "" {
		if err := agent.CompleteEnrollmentAttempt(w.dataDir, attemptID); err != nil {
			return false, fmt.Errorf("complete enrollment attempt: %w", err)
		}
	}
	w.client.SetToken("")
	_ = DeleteServerToken(w.dataDir)
	_ = SaveServerJoinToken(w.dataDir, "")
	return true, nil
}

func (w *UploadWorker) syncWebSocketTLSConfig() {
	w.wsClientMu.Lock()
	defer w.wsClientMu.Unlock()
	if w.wsClient != nil {
		w.wsClient.SetTLSConfig(w.client.TLSConfig())
	}
}

// heartbeatLoop sends periodic heartbeats to the server
func (w *UploadWorker) heartbeatLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.heartbeatInterval)
	defer ticker.Stop()

	// Send initial heartbeat immediately
	w.sendHeartbeat()

	for {
		select {
		case <-ticker.C:
			w.sendHeartbeat()
		case <-w.stopCh:
			return
		}
	}
}

// buildHeartbeatMetadata prepares shared metadata fields so WebSocket and HTTP
// heartbeats keep server-side agent records in sync.
func (w *UploadWorker) buildHeartbeatMetadata() map[string]interface{} {
	meta := map[string]interface{}{
		"status":       "active",
		"platform":     agent.GetPlatformInfo(),
		"os_version":   agent.GetOSVersionDetailed(),
		"architecture": runtime.GOARCH,
		"go_version":   runtime.Version(),
		"num_cpu":      runtime.NumCPU(),
	}

	// Add runtime memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	meta["heap_alloc_mb"] = int64(memStats.HeapAlloc / (1024 * 1024))
	meta["sys_mb"] = int64(memStats.Sys / (1024 * 1024))
	meta["goroutines"] = runtime.NumGoroutine()

	// Add database size if available
	if w.dataDir != "" {
		dbPath := filepath.Join(w.dataDir, "devices.db")
		if info, err := os.Stat(dbPath); err == nil {
			meta["db_size_bytes"] = info.Size()
		}
	}

	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		meta["hostname"] = hostname
	}

	if w.versionInfo != nil {
		if version := strings.TrimSpace(w.versionInfo.Version); version != "" {
			meta["version"] = version
		}
		if proto := strings.TrimSpace(w.versionInfo.ProtocolVersion); proto != "" {
			meta["protocol_version"] = proto
		}
		if buildType := strings.TrimSpace(w.versionInfo.BuildType); buildType != "" {
			meta["build_type"] = buildType
		}
		if commit := strings.TrimSpace(w.versionInfo.GitCommit); commit != "" {
			meta["git_commit"] = commit
		}
	}

	return meta
}

// sendHeartbeat sends a single heartbeat with retry logic
func (w *UploadWorker) sendHeartbeat() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try WebSocket first if available
	w.wsClientMu.RLock()
	wsClient := w.wsClient
	w.wsClientMu.RUnlock()

	if wsClient != nil && wsClient.IsConnected() {
		// Get device count to include in heartbeat
		visibleOnly := true
		devices, err := w.store.List(ctx, storage.DeviceFilter{Visible: &visibleOnly})
		deviceCount := 0
		if err == nil {
			deviceCount = len(devices)
		}

		// Send heartbeat over WebSocket with metadata parity to HTTP heartbeats
		heartbeatData := w.buildHeartbeatMetadata()
		heartbeatData["device_count"] = deviceCount
		if settingsVersion := strings.TrimSpace(w.currentSettingsVersion()); settingsVersion != "" {
			heartbeatData["settings_version"] = settingsVersion
		}

		if err := wsClient.SendHeartbeat(heartbeatData); err != nil {
			w.logger.Warn("WebSocket heartbeat failed, falling back to HTTP", "error", err)
			// Fall through to HTTP heartbeat
		} else {
			// WebSocket heartbeats do not return snapshots, so mirror the heartbeat
			// over HTTP to apply a changed server snapshot immediately.
			if result, heartbeatErr := w.client.HeartbeatWithVersion(ctx, w.currentSettingsVersion(), w.versionInfo); heartbeatErr == nil {
				w.handleHeartbeatSettings(result)
			}
			w.mu.Lock()
			w.lastHeartbeat = time.Now()
			w.mu.Unlock()
			w.logger.Debug("Heartbeat sent via WebSocket")
			return
		}
	}

	// Fall back to HTTP heartbeat
	var hbResult *agent.HeartbeatResult
	err := w.retryWithBackoff(func() error {
		result, err := w.client.HeartbeatWithVersion(ctx, w.currentSettingsVersion(), w.versionInfo)
		if err == nil {
			hbResult = result
		}
		return err
	})

	if err != nil {
		w.logger.Warn("HTTP heartbeat failed after retries", "error", err)
	} else {
		if hbResult != nil {
			w.handleHeartbeatSettings(hbResult)
		}
		w.mu.Lock()
		w.lastHeartbeat = time.Now()
		w.mu.Unlock()
		w.logger.Debug("Heartbeat sent via HTTP")
	}
}

// uploadLoop handles periodic uploads of devices and metrics
func (w *UploadWorker) uploadLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.uploadInterval)
	defer ticker.Stop()

	// Upload immediately on start (don't wait for first interval)
	w.doUpload()

	for {
		select {
		case <-ticker.C:
			w.doUpload()
		case <-w.stopCh:
			return
		}
	}
}

// doUpload performs a complete upload cycle (devices + metrics)
func (w *UploadWorker) doUpload() {
	w.logger.Debug("Starting upload cycle")

	// Upload devices first
	if err := w.uploadDevices(); err != nil {
		w.logger.Error("Device upload failed", "error", err)
		// Continue to metrics even if devices failed (partial success OK)
	}

	// Then upload metrics
	if err := w.uploadMetrics(); err != nil {
		w.logger.Error("Metrics upload failed", "error", err)
	}

	w.logger.Debug("Upload cycle complete")
}

// uploadDevices reads devices from store and uploads them
func (w *UploadWorker) uploadDevices() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get all visible devices from store
	visibleTrue := true
	filter := storage.DeviceFilter{
		Visible: &visibleTrue,
	}

	devices, err := w.store.List(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list devices: %w", err)
	}

	if len(devices) == 0 {
		w.logger.Debug("No devices to upload")
		return nil
	}

	// Convert devices to upload format
	deviceMaps := make([]interface{}, 0, len(devices))
	for _, dev := range devices {
		deviceMap := map[string]interface{}{
			"serial":           dev.Serial,
			"ip":               dev.IP,
			"manufacturer":     dev.Manufacturer,
			"model":            dev.Model,
			"hostname":         dev.Hostname,
			"firmware":         dev.Firmware,
			"mac_address":      dev.MACAddress,
			"subnet_mask":      dev.SubnetMask,
			"gateway":          dev.Gateway,
			"consumables":      dev.Consumables,
			"status_messages":  dev.StatusMessages,
			"last_seen":        dev.LastSeen,
			"first_seen":       dev.FirstSeen,
			"discovery_method": dev.DiscoveryMethod,
			"asset_number":     dev.AssetNumber,
			"location":         dev.Location,
			"description":      dev.Description,
			"web_ui_url":       dev.WebUIURL,
			"raw_data":         dev.RawData,
			// Device classification fields (for unified device view)
			"device_type":         dev.DeviceType,
			"source_type":         dev.SourceType,
			"is_usb":              dev.IsUSB,
			"port_name":           dev.PortName,
			"driver_name":         dev.DriverName,
			"is_default":          dev.IsDefault,
			"is_shared":           dev.IsShared,
			"spooler_status":      dev.SpoolerStatus,
			"usb_webui_available": dev.UsbWebUIAvailable,
		}
		deviceMaps = append(deviceMaps, deviceMap)
	}

	// Upload with retry
	err = w.retryWithBackoff(func() error {
		return w.client.UploadDevices(ctx, deviceMaps)
	})

	if err != nil {
		return fmt.Errorf("failed to upload devices: %w", err)
	}

	w.mu.Lock()
	w.lastDeviceUpload = time.Now()
	w.mu.Unlock()

	w.logger.Info("Devices uploaded successfully", "count", len(devices))
	return nil
}

// uploadMetrics reads latest metrics from store and uploads them
func (w *UploadWorker) uploadMetrics() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get all visible devices to fetch their latest metrics
	visibleTrue := true
	filter := storage.DeviceFilter{
		Visible: &visibleTrue,
	}

	devices, err := w.store.List(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list devices for metrics: %w", err)
	}

	if len(devices) == 0 {
		w.logger.Debug("No devices for metrics upload")
		return nil
	}

	// Get latest metrics for each device
	var metricMaps []interface{}

	for _, dev := range devices {
		metrics, err := w.store.GetLatestMetrics(ctx, dev.Serial)
		if err != nil || metrics == nil {
			// No metrics for this device yet, skip
			continue
		}

		metricMap := map[string]interface{}{
			"serial":       metrics.Serial,
			"timestamp":    metrics.Timestamp,
			"page_count":   metrics.PageCount,
			"color_pages":  metrics.ColorPages,
			"mono_pages":   metrics.MonoPages,
			"scan_count":   metrics.ScanCount,
			"toner_levels": metrics.TonerLevels,
		}
		metricMaps = append(metricMaps, metricMap)
	}

	if len(metricMaps) == 0 {
		w.logger.Debug("No metrics to upload")
		return nil
	}

	// Upload with retry
	err = w.retryWithBackoff(func() error {
		return w.client.UploadMetrics(ctx, metricMaps)
	})

	if err != nil {
		return fmt.Errorf("failed to upload metrics: %w", err)
	}

	w.mu.Lock()
	w.lastMetricsUpload = time.Now()
	w.mu.Unlock()

	w.logger.Info("Metrics uploaded successfully", "count", len(metricMaps))
	return nil
}

// retryWithBackoff retries a function with exponential backoff
func (w *UploadWorker) retryWithBackoff(fn func() error) error {
	var lastErr error

	for attempt := 0; attempt < w.retryAttempts; attempt++ {
		err := fn()
		if err == nil {
			return nil // Success
		}

		lastErr = err

		// Don't retry on the last attempt
		if attempt == w.retryAttempts-1 {
			break
		}

		// Exponential backoff: 2s, 4s, 8s, etc.
		backoff := w.retryBackoff * time.Duration(1<<attempt)
		w.logger.Debug("Retry after backoff",
			"attempt", attempt+1,
			"backoff", backoff,
			"error", err)

		select {
		case <-time.After(backoff):
			// Continue to next attempt
		case <-w.stopCh:
			return fmt.Errorf("stopped during retry")
		}
	}

	return fmt.Errorf("failed after %d attempts: %w", w.retryAttempts, lastErr)
}

// GetStats returns current upload worker statistics
func (w *UploadWorker) GetStats() map[string]interface{} {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return map[string]interface{}{
		"last_heartbeat":      w.lastHeartbeat,
		"last_device_upload":  w.lastDeviceUpload,
		"last_metrics_upload": w.lastMetricsUpload,
		"heartbeat_interval":  w.heartbeatInterval.String(),
		"upload_interval":     w.uploadInterval.String(),
	}
}
