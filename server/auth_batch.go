package main

import (
	"net/http"
	"printmaster/server/storage"
)

func authenticatedBatchAgent(w http.ResponseWriter, r *http.Request, claimedID string) (*storage.Agent, bool) {
	a, ok := r.Context().Value(agentContextKey).(*storage.Agent)
	if !ok || a == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	if claimedID != "" && claimedID != a.AgentID {
		http.Error(w, "agent identity mismatch", http.StatusForbidden)
		return nil, false
	}
	return a, true
}
