package authz

import (
	"errors"
	"fmt"
	"strings"

	"printmaster/server/storage"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

// Action represents a permissionable operation within the server API surface.
type Action string

const (
	ActionTenantsRead      Action = "tenants.read"
	ActionTenantsWrite     Action = "tenants.write"
	ActionJoinTokensRead   Action = "join_tokens.read"
	ActionJoinTokensWrite  Action = "join_tokens.write"
	ActionPackagesGenerate Action = "packages.generate"

	ActionConfigRead         Action = "config.read"
	ActionEventsSubscribe    Action = "events.subscribe"
	ActionUIWebsocketConnect Action = "ui.websocket.connect"

	ActionSSOProvidersRead  Action = "sso.providers.read"
	ActionSSOProvidersWrite Action = "sso.providers.write"

	ActionUsersRead     Action = "users.read"
	ActionUsersWrite    Action = "users.write"
	ActionSessionsRead  Action = "sessions.read"
	ActionSessionsWrite Action = "sessions.write"

	ActionAgentsRead   Action = "agents.read"
	ActionAgentsWrite  Action = "agents.write"
	ActionAgentsDelete Action = "agents.delete"

	ActionDevicesRead            Action = "devices.read"
	ActionDevicesWrite           Action = "devices.write"
	ActionDevicesDelete          Action = "devices.delete"
	ActionDeviceCredentialsWrite Action = "devices.credentials.write"

	ActionMetricsSummaryRead      Action = "metrics.summary.read"
	ActionMetricsHistoryRead      Action = "metrics.history.read"
	ActionMetricsServerGlobalRead Action = "metrics.server.global.read"

	ActionProxyAgentConnect  Action = "proxy.agent"
	ActionProxyDeviceConnect Action = "proxy.device"

	// Granular settings permissions
	// Server settings (SMTP, branding, ports, self-update) - admin only
	ActionSettingsServerRead  Action = "settings.server.read"
	ActionSettingsServerWrite Action = "settings.server.write"

	// Fleet settings (discovery, snmp, features) - tenant-scoped for operators+
	ActionSettingsFleetRead  Action = "settings.fleet.read"
	ActionSettingsFleetWrite Action = "settings.fleet.write"
	// Global fleet settings are server-wide and therefore admin-only.  Tenant
	// operators use ActionSettingsFleetRead/Write with a tenant ResourceRef.
	ActionSettingsFleetGlobalRead  Action = "settings.fleet.global.read"
	ActionSettingsFleetGlobalWrite Action = "settings.fleet.global.write"

	// Alert settings (rules, channels, policies) - tenant-scoped for operators+
	ActionSettingsAlertsRead  Action = "settings.alerts.read"
	ActionSettingsAlertsWrite Action = "settings.alerts.write"
	// Global alert settings and summaries have no tenant key and are admin-only.
	ActionSettingsAlertsGlobalRead  Action = "settings.alerts.global.read"
	ActionSettingsAlertsGlobalWrite Action = "settings.alerts.global.write"

	ActionLogsRead      Action = "logs.read"
	ActionLogsWrite     Action = "logs.write"
	ActionAuditLogsRead Action = "audit.logs.read"

	ActionReleasesRead  Action = "releases.read"
	ActionReleasesWrite Action = "releases.write"
)

// ResourceRef carries contextual identifiers relevant for authorization checks.
type ResourceRef struct {
	TenantIDs []string
}

// Subject describes the caller being authorized.
type Subject struct {
	Role             storage.Role
	AllowedTenantIDs []string
	IsAdmin          bool
}

// Authorize ensures subject can perform action on the resource.

func Authorize(subject Subject, action Action, resource ResourceRef) error {
	if !roleAllows(subject.Role, action) {
		return fmt.Errorf("%w: role %s cannot perform %s", ErrForbidden, subject.Role, action)
	}

	if len(resource.TenantIDs) > 0 && !subject.IsAdmin {
		allowed := make(map[string]struct{}, len(subject.AllowedTenantIDs))
		for _, tid := range subject.AllowedTenantIDs {
			allowed[tid] = struct{}{}
		}
		for _, tid := range resource.TenantIDs {
			if tid == "" {
				continue
			}
			if _, ok := allowed[tid]; !ok {
				return fmt.Errorf("%w: tenant %s not permitted", ErrForbidden, tid)
			}
		}
	}

	return nil
}

var rolePolicies = map[storage.Role][]string{
	storage.RoleAdmin: {"*"},
	storage.RoleOperator: {
		"config.read",
		"events.subscribe",
		"ui.websocket.connect",
		"agents.*",
		"packages.generate",
		"devices.read",
		"devices.write",
		"devices.delete",
		"devices.credentials.write",
		"metrics.summary.read",
		"metrics.history.read",
		"proxy.agent",
		"proxy.device",
		// Granular settings permissions (tenant-scoped via ResourceRef)
		"settings.fleet.read",   // Read fleet settings (discovery, snmp, features)
		"settings.fleet.write",  // Write fleet settings
		"settings.alerts.read",  // Read alert rules/channels
		"settings.alerts.write", // Write alert rules/channels
	},
	storage.RoleViewer: {
		"config.read",
		"events.subscribe",
		"ui.websocket.connect",
		"agents.read",
		"devices.read",
		"metrics.summary.read",
		"metrics.history.read",
		// Granular settings permissions (read-only, tenant-scoped)
		"settings.fleet.read",  // Read fleet settings
		"settings.alerts.read", // Read alert rules
	},
}

func roleAllows(role storage.Role, action Action) bool {
	patterns, ok := rolePolicies[role]
	if !ok {
		return false
	}

	needle := strings.ToLower(string(action))
	for _, pattern := range patterns {
		switch {
		case pattern == "*":
			return true
		case strings.EqualFold(pattern, needle):
			return true
		case strings.HasSuffix(pattern, ".*"):
			prefix := strings.TrimSuffix(strings.ToLower(pattern), ".*")
			if strings.HasPrefix(needle, prefix+".") {
				return true
			}
		}
	}
	return false
}
