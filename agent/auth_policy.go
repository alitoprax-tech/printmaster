package main

import "net/http"

// Explicitly list read operations: legacy GET endpoints can also change state.
func agentRoleAllows(p *AgentPrincipal, r *http.Request) bool {
	if p == nil {
		return false
	}
	if p.Role == "admin" {
		return true
	}
	if p.Role != "viewer" && p.Role != "operator" {
		return false
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		switch r.URL.Path {
		case "/", "/events", "/devices/discovered", "/devices/list", "/devices/get",
			"/api/devices/profile", "/api/devices/audit", "/api/devices/usage",
			"/api/devices/metrics/latest", "/api/devices/metrics/bounds", "/api/devices/metrics/history",
			"/api/autoupdate/status", "/scan_metrics", "/api/usb-printers", "/api/usb-printers/status",
			"/api/usb-printers/metrics":
			return true
		}
	}
	if p.Role == "operator" && r.Method == http.MethodPost {
		switch r.URL.Path {
		case "/devices/refresh", "/devices/metrics/collect", "/devices/save", "/devices/save/all", "/devices/update":
			return true
		}
	}
	return false
}
