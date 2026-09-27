package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"printmaster/server/storage"
)

func TestAgentTelemetryRejectsUnboundedAndInvalidInput(t *testing.T) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	for _, tc := range []struct{ name, body, route string }{
		{"device count", fmt.Sprintf(`{"timestamp":%q,"devices":[%s]}`, timestamp, strings.TrimSuffix(strings.Repeat(`{"serial":"s"},`, 251), ",")), "devices"},
		{"metric count", fmt.Sprintf(`{"timestamp":%q,"metrics":[%s]}`, timestamp, strings.TrimSuffix(strings.Repeat(`{"serial":"s"},`, 501), ",")), "metrics"},
		{"negative counter", fmt.Sprintf(`{"timestamp":%q,"metrics":[{"serial":"s","page_count":-1}]}`, timestamp), "metrics"},
		{"counter overflow", fmt.Sprintf(`{"timestamp":%q,"metrics":[{"serial":"s","page_count":9007199254740999}]}`, timestamp), "metrics"},
		{"wrong counter type", fmt.Sprintf(`{"timestamp":%q,"metrics":[{"serial":"s","page_count":"lots"}]}`, timestamp), "metrics"},
		{"invalid toner", fmt.Sprintf(`{"timestamp":%q,"metrics":[{"serial":"s","toner_levels":{"black":999}}]}`, timestamp), "metrics"},
		{"too many toners", fmt.Sprintf(`{"timestamp":%q,"metrics":[{"serial":"s","toner_levels":{%s}}]}`, timestamp, makeTonerEntries(33)), "metrics"},
		{"bad IP", fmt.Sprintf(`{"timestamp":%q,"devices":[{"serial":"s","ip":"metadata.internal"}]}`, timestamp), "devices"},
		{"bad MAC", fmt.Sprintf(`{"timestamp":%q,"devices":[{"serial":"s","mac_address":"invalid"}]}`, timestamp), "devices"},
		{"long serial", fmt.Sprintf(`{"timestamp":%q,"devices":[{"serial":%q}]}`, timestamp, strings.Repeat("s", 129)), "devices"},
		{"nested raw data", fmt.Sprintf(`{"timestamp":%q,"devices":[{"serial":"s","raw_data":{"a":{"b":{"c":{"d":{"e":{"f":{}}}}}}}}]}`, timestamp), "devices"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/"+tc.route+"/batch", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			if tc.route == "devices" {
				handleDevicesBatch(w, r)
			} else {
				handleMetricsBatch(w, r)
			}
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", w.Code)
			}
		})
	}
}

func TestAgentHeartbeatRejectsHostileMetadata(t *testing.T) {
	for _, body := range []string{
		`{"status":"<script>alert(1)</script>"}`,
		`{"status":"active","ip":"metadata.internal"}`,
		`{"status":"active","hostname":"` + strings.Repeat("x", 513) + `"}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/agents/heartbeat", strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), agentContextKey, &storage.Agent{AgentID: "heartbeat-test"}))
		w := httptest.NewRecorder()
		handleAgentHeartbeat(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid heartbeat got %d", w.Code)
		}
	}
}

func TestAgentReportTimeRejectsImpossibleDates(t *testing.T) {
	now := time.Now().UTC()
	for _, reported := range []time.Time{time.Time{}, now.Add(time.Hour), time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if validateAgentReportTime(reported, now) == nil {
			t.Fatalf("accepted impossible timestamp %v", reported)
		}
	}
}

func makeTonerEntries(count int) string {
	entries := make([]string, count)
	for i := range entries {
		entries[i] = fmt.Sprintf(`"toner%d":50`, i)
	}
	return strings.Join(entries, ",")
}

func TestAgentTelemetryPreservesVendorFieldsWithinBound(t *testing.T) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices/batch", strings.NewReader(fmt.Sprintf(`{"timestamp":%q,"devices":[{"serial":"s","ip":"192.0.2.15","raw_data":{"vendor_field":"value"}}]}`, timestamp)))
	batch, devices, raw, err := decodeAgentDeviceBatch(r)
	if err != nil || len(devices) != 1 || batch.Timestamp.IsZero() || raw[0]["raw_data"].(map[string]interface{})["vendor_field"] != "value" {
		t.Fatalf("valid bounded vendor field lost: %+v %+v %v", devices, raw, err)
	}
}
