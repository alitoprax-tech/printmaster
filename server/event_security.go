package main

import (
	"context"
	"net/http"
	"printmaster/server/storage"
)

// Recheck the session for long-lived streams so logout and role changes take effect.
func currentStreamPrincipal(r *http.Request) *Principal {
	u, err := loadUserForSessionToken(sessionTokenFromRequest(r))
	if err != nil {
		return nil
	}
	return newPrincipal(u)
}

// Unscoped events (logs, fleet summaries, internal errors) are administrator-only.
// For agent events, ownership always comes from storage, never a supplied tenant_id.
func eventVisibleToPrincipal(ctx context.Context, store storage.Store, p *Principal, data map[string]interface{}) bool {
	if p == nil {
		return false
	}
	if p.IsAdmin() {
		return true
	}
	if agentID, ok := data["agent_id"].(string); ok && agentID != "" {
		if store == nil {
			return false
		}
		agent, err := store.GetAgent(ctx, agentID)
		return err == nil && agent != nil && p.CanAccessTenant(agent.TenantID)
	}
	if tenantID, ok := data["tenant_id"].(string); ok && tenantID != "" {
		return p.CanAccessTenant(tenantID)
	}
	return false
}

// Reports can aggregate the whole fleet and create scheduled exports. Until report
// execution carries an immutable tenant scope, restrict that surface to administrators.
func requireReportAdmin(w http.ResponseWriter, r *http.Request) bool {
	if p := getPrincipal(r); p != nil && p.IsAdmin() {
		return true
	}
	http.Error(w, "report administration requires administrator role", http.StatusForbidden)
	return false
}
