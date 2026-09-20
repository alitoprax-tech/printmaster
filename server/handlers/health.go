package handlers

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HealthAPI provides HTTP handlers for health checks and version information.
type HealthAPI struct {
	version         string
	buildTime       string
	gitCommit       string
	buildType       string
	protocolVersion string
	processStart    time.Time
	tenancyChecker  func() bool // Optional function to check if tenancy is enabled
}

// HealthAPIOptions configures the health API.
type HealthAPIOptions struct {
	Version         string
	BuildTime       string
	GitCommit       string
	BuildType       string
	ProtocolVersion string
	ProcessStart    time.Time
	TenancyChecker  func() bool
}

// NewHealthAPI creates a new health API instance.
func NewHealthAPI(opts HealthAPIOptions) *HealthAPI {
	return &HealthAPI{
		version:         opts.Version,
		buildTime:       opts.BuildTime,
		gitCommit:       opts.GitCommit,
		buildType:       opts.BuildType,
		protocolVersion: opts.ProtocolVersion,
		processStart:    opts.ProcessStart,
		tenancyChecker:  opts.TenancyChecker,
	}
}

// RegisterRoutes registers the health and version routes.
func (api *HealthAPI) RegisterRoutes(mux *http.ServeMux) {
	if mux == nil {
		mux = http.DefaultServeMux
	}
	mux.HandleFunc("/health", api.HandleHealth)
	mux.HandleFunc("/api/version", api.HandleVersion)
}

// HandleHealth handles GET /health - simple health check endpoint.
// This endpoint is public (no authentication required) for use by load balancers
// and container orchestrators.
func (api *HealthAPI) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
	})
}

// HandleVersion handles GET /api/version - returns server version information.
// This endpoint is public (no authentication required).
func (api *HealthAPI) HandleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	// Keep the unauthenticated endpoint useful for compatibility checks while
	// avoiding build paths, commit IDs, runtime versions and uptime details that
	// make internet-facing instances easy to fingerprint.
	resp := map[string]interface{}{
		"version":          api.version,
		"protocol_version": api.protocolVersion,
	}
	if api.tenancyChecker != nil {
		resp["tenancy_enabled"] = api.tenancyChecker()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// HealthCheckConfig contains configuration for health checks.
type HealthCheckConfig struct {
	HTTPPort      int
	HTTPSPort     int
	BehindProxy   bool
	ProxyUseHTTPS bool
}

// healthAttempt represents a single health check attempt configuration.
type healthAttempt struct {
	URL      string
	Insecure bool
}

// RunHealthCheck probes the local /health endpoint over HTTP/HTTPS using configured ports.
// Returns nil on success; otherwise an error summarizing all failed attempts.
func RunHealthCheck(cfg HealthCheckConfig) error {
	// Determine which endpoints to probe based on configuration.
	// The logic matches the actual server startup behavior:
	// - BehindProxy + !ProxyUseHTTPS → HTTP only (proxy terminates TLS)
	// - BehindProxy + ProxyUseHTTPS → HTTPS only (end-to-end encryption)
	// - !BehindProxy (standalone) → HTTPS only
	attempts := make([]healthAttempt, 0, 2)

	if cfg.BehindProxy && !cfg.ProxyUseHTTPS {
		// Reverse proxy mode with HTTP: only probe HTTP since that's all that's running
		if cfg.HTTPPort > 0 {
			attempts = append(attempts, healthAttempt{URL: fmt.Sprintf("http://127.0.0.1:%d/health", cfg.HTTPPort)})
		}
	} else if cfg.BehindProxy && cfg.ProxyUseHTTPS {
		// Reverse proxy mode with end-to-end HTTPS: only probe HTTPS
		if cfg.HTTPSPort > 0 {
			attempts = append(attempts, healthAttempt{URL: fmt.Sprintf("https://127.0.0.1:%d/health", cfg.HTTPSPort), Insecure: true})
		}
	} else {
		// Standalone mode (default): HTTPS only
		// However, if HTTPS port is 0/disabled but HTTP port is set, try HTTP (test compatibility)
		if cfg.HTTPSPort > 0 {
			attempts = append(attempts, healthAttempt{URL: fmt.Sprintf("https://127.0.0.1:%d/health", cfg.HTTPSPort), Insecure: true})
		} else if cfg.HTTPPort > 0 {
			// Fallback to HTTP if HTTPS is explicitly disabled
			attempts = append(attempts, healthAttempt{URL: fmt.Sprintf("http://127.0.0.1:%d/health", cfg.HTTPPort)})
		}
	}

	// Do not mistake an unrelated service on the default port for this instance.
	if len(attempts) == 0 {
		return fmt.Errorf("no health endpoints to probe")
	}

	var errs []string
	for _, attempt := range attempts {
		if err := probeHealthEndpoint(attempt.URL, attempt.Insecure); err != nil {
			errMsg := fmt.Sprintf("%s: %v", attempt.URL, err)
			errs = append(errs, errMsg)
			continue
		}
		return nil
	}

	if len(errs) == 0 {
		return fmt.Errorf("no health endpoints to probe")
	}

	return fmt.Errorf("%s", strings.Join(errs, "; "))
}

// probeHealthEndpoint sends a GET request to the health endpoint and validates the response.
func probeHealthEndpoint(endpoint string, insecure bool) error {
	client := &http.Client{Timeout: 5 * time.Second}
	if insecure {
		if !isLoopbackHealthEndpoint(endpoint) {
			return fmt.Errorf("insecure health probes are restricted to loopback")
		}
		// Skip TLS verification for self-signed/local certs used by the server.
		// #nosec G402 -- the endpoint is checked above and is fixed loopback;
		// self-signed certificates are accepted only for this local probe.
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var payload struct {
		Status string `json:"status"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&payload); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if payload.Status != "healthy" {
		return fmt.Errorf("unhealthy status: %s", payload.Status)
	}

	return nil
}

func isLoopbackHealthEndpoint(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := strings.ToLower(strings.Trim(parsed.Hostname(), "[]"))
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}
