package main

import (
	"strings"
	"testing"
	"time"

	agentpkg "printmaster/agent/agent"
	pmsettings "printmaster/common/settings"
)

func TestChunkAgentUploadItemsHonorsCountAndBytes(t *testing.T) {
	items := make([]interface{}, 501)
	for i := range items {
		items[i] = map[string]interface{}{"serial": "device"}
	}
	chunks, err := chunkAgentUploadItems(items, 250, 512<<10)
	if err != nil || len(chunks) != 3 || len(chunks[0]) != 250 || len(chunks[1]) != 250 || len(chunks[2]) != 1 {
		t.Fatalf("count chunks: %v %v", len(chunks), err)
	}
	items = []interface{}{map[string]interface{}{"raw_data": strings.Repeat("x", 400)}, map[string]interface{}{"raw_data": strings.Repeat("x", 400)}}
	chunks, err = chunkAgentUploadItems(items, 250, 512)
	if err != nil || len(chunks) != 2 {
		t.Fatalf("byte chunks: %v %v", len(chunks), err)
	}
	if _, err = chunkAgentUploadItems(items, 250, 16); err == nil {
		t.Fatal("oversize single item accepted")
	}
}

type stubLogger struct{}

func (stubLogger) Error(string, ...interface{}) {}
func (stubLogger) Warn(string, ...interface{})  {}
func (stubLogger) Info(string, ...interface{})  {}
func (stubLogger) Debug(string, ...interface{}) {}

func TestUploadWorkerHandleHeartbeatSettingsPersistsSnapshot(t *testing.T) {
	store := newFakeConfigStore()
	mgr := NewSettingsManager(store)
	prev := settingsManager
	settingsManager = mgr
	t.Cleanup(func() { settingsManager = prev })

	worker := &UploadWorker{settings: mgr, logger: stubLogger{}}
	snap := &agentpkg.SettingsSnapshot{
		Version:       "v1",
		SchemaVersion: "schema-1",
		UpdatedAt:     time.Unix(500, 0),
		Settings:      pmsettings.DefaultSettings(),
	}

	worker.handleHeartbeatSettings(&agentpkg.HeartbeatResult{Snapshot: snap})
	if mgr.CurrentVersion() != "v1" {
		t.Fatalf("expected manager version to update")
	}
	if store.setCount(serverManagedSettingsKey) != 1 {
		t.Fatalf("expected snapshot persisted once, got %d", store.setCount(serverManagedSettingsKey))
	}

	worker.handleHeartbeatSettings(&agentpkg.HeartbeatResult{Snapshot: snap, SettingsVersion: snap.Version})
	if store.setCount(serverManagedSettingsKey) != 1 {
		t.Fatalf("expected no-op when version matches")
	}
}

func TestUploadWorkerHandleHeartbeatSettingsIgnoresNilSnapshot(t *testing.T) {
	worker := &UploadWorker{settings: nil, logger: stubLogger{}}
	worker.handleHeartbeatSettings(&agentpkg.HeartbeatResult{})
}
