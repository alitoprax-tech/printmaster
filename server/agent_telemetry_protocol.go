package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	maxAgentDeviceBatch      = 250
	maxAgentMetricBatch      = 500
	maxAgentTelemetryDepth   = 6
	maxAgentTelemetryMembers = 256
	maxAgentCounter          = 2_000_000_000
)

type agentDeviceInput struct {
	Serial            string `json:"serial"`
	IP                string `json:"ip"`
	MAC               string `json:"mac_address"`
	Manufacturer      string `json:"manufacturer"`
	Model             string `json:"model"`
	Hostname          string `json:"hostname"`
	Firmware          string `json:"firmware"`
	DeviceType        string `json:"device_type"`
	SourceType        string `json:"source_type"`
	IsUSB             bool   `json:"is_usb"`
	PortName          string `json:"port_name"`
	DriverName        string `json:"driver_name"`
	IsDefault         bool   `json:"is_default"`
	IsShared          bool   `json:"is_shared"`
	SpoolerStatus     string `json:"spooler_status"`
	USBWebUIAvailable bool   `json:"usb_webui_available"`
}

type agentMetricInput struct {
	Serial      string                 `json:"serial"`
	PageCount   int64                  `json:"page_count"`
	ColorPages  int64                  `json:"color_pages"`
	MonoPages   int64                  `json:"mono_pages"`
	ScanCount   int64                  `json:"scan_count"`
	TonerLevels map[string]interface{} `json:"toner_levels"`
}

type agentDeviceBatch struct {
	AgentID   string            `json:"agent_id"`
	Timestamp time.Time         `json:"timestamp"`
	Devices   []json.RawMessage `json:"devices"`
}

type agentMetricBatch struct {
	AgentID   string            `json:"agent_id"`
	Timestamp time.Time         `json:"timestamp"`
	Metrics   []json.RawMessage `json:"metrics"`
}

func validateAgentReportTime(timestamp time.Time, now time.Time) error {
	if timestamp.IsZero() || timestamp.Before(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) || timestamp.After(now.Add(5*time.Minute)) {
		return errors.New("invalid telemetry timestamp")
	}
	return nil
}

func validateAgentField(value string, limit int) error {
	if len(value) > limit || strings.ContainsRune(value, '\x00') {
		return errors.New("telemetry field exceeds size or contains NUL")
	}
	return nil
}

// Bound every retained unknown/raw-data field before unmarshalling it into an
// interface tree. Legacy vendor fields are preserved but cannot be unbounded.
func validateAgentJSONShape(value interface{}, depth int) error {
	if depth > maxAgentTelemetryDepth {
		return errors.New("telemetry JSON nesting exceeds limit")
	}
	switch v := value.(type) {
	case map[string]interface{}:
		if len(v) > maxAgentTelemetryMembers {
			return errors.New("too many telemetry fields")
		}
		for key, item := range v {
			if err := validateAgentField(key, 128); err != nil {
				return err
			}
			if err := validateAgentJSONShape(item, depth+1); err != nil {
				return err
			}
		}
	case []interface{}:
		if len(v) > maxAgentTelemetryMembers {
			return errors.New("telemetry list too long")
		}
		for _, item := range v {
			if err := validateAgentJSONShape(item, depth+1); err != nil {
				return err
			}
		}
	case string:
		return validateAgentField(v, 4096)
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > 1e15 {
			return errors.New("invalid telemetry number")
		}
	case bool, nil:
	default:
		return errors.New("invalid telemetry value")
	}
	return nil
}

func decodeAgentTelemetryItem(raw json.RawMessage, target interface{}) (map[string]interface{}, error) {
	if len(raw) > 64<<10 {
		return nil, errors.New("telemetry item exceeds size limit")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var retained map[string]interface{}
	if err := dec.Decode(&retained); err != nil || retained == nil {
		return nil, errors.New("telemetry item must be an object")
	}
	if err := validateAgentJSONShape(retained, 0); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return nil, err
	}
	return retained, nil
}

func validateAgentDevice(input agentDeviceInput) error {
	if input.Serial == "" {
		return errors.New("device serial is required")
	}
	for _, field := range []string{input.Serial, input.Manufacturer, input.Model, input.Hostname, input.Firmware, input.PortName, input.DriverName, input.SpoolerStatus} {
		if err := validateAgentField(field, 256); err != nil {
			return err
		}
	}
	if len(input.Serial) > 128 {
		return errors.New("device serial too long")
	}
	if err := validateAgentField(input.IP, 64); err != nil {
		return err
	}
	if input.IP != "" && net.ParseIP(input.IP) == nil {
		return errors.New("invalid device IP")
	}
	if err := validateAgentField(input.MAC, 64); err != nil {
		return err
	}
	if input.MAC != "" {
		if _, err := net.ParseMAC(input.MAC); err != nil {
			return errors.New("invalid device MAC")
		}
	}
	for _, field := range []string{input.DeviceType, input.SourceType} {
		if err := validateAgentField(field, 64); err != nil {
			return err
		}
	}
	return nil
}

func validateAgentMetric(input agentMetricInput) error {
	if input.Serial == "" || len(input.Serial) > 128 {
		return errors.New("invalid metric serial")
	}
	for _, count := range []int64{input.PageCount, input.ColorPages, input.MonoPages, input.ScanCount} {
		if count < 0 || count > maxAgentCounter {
			return errors.New("invalid page counter")
		}
	}
	if len(input.TonerLevels) > 32 {
		return errors.New("too many toner entries")
	}
	for name, value := range input.TonerLevels {
		if err := validateAgentField(name, 64); err != nil {
			return err
		}
		number, ok := value.(float64)
		if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number < 0 || number > 100 {
			return errors.New("invalid toner level")
		}
	}
	return nil
}

func validateAgentHeartbeatMetadata(status, ip string, fields ...string) error {
	switch status {
	case "", "active", "inactive", "offline", "online", "idle", "degraded", "error":
	default:
		return errors.New("invalid Agent heartbeat status")
	}
	if err := validateAgentField(ip, 64); err != nil {
		return err
	}
	if ip != "" && net.ParseIP(ip) == nil {
		return errors.New("invalid Agent heartbeat IP")
	}
	for _, field := range fields {
		if err := validateAgentField(field, 512); err != nil {
			return err
		}
	}
	return nil
}

func decodeAgentDeviceBatch(r *http.Request) (agentDeviceBatch, []agentDeviceInput, []map[string]interface{}, error) {
	var batch agentDeviceBatch
	if err := decodeJSONBody(r, &batch); err != nil {
		return batch, nil, nil, err
	}
	if len(batch.Devices) > maxAgentDeviceBatch {
		return batch, nil, nil, fmt.Errorf("device batch exceeds %d entries", maxAgentDeviceBatch)
	}
	devices := make([]agentDeviceInput, 0, len(batch.Devices))
	raw := make([]map[string]interface{}, 0, len(batch.Devices))
	for _, item := range batch.Devices {
		var device agentDeviceInput
		retained, err := decodeAgentTelemetryItem(item, &device)
		if err != nil {
			return batch, nil, nil, err
		}
		if err = validateAgentDevice(device); err != nil {
			return batch, nil, nil, err
		}
		devices = append(devices, device)
		raw = append(raw, retained)
	}
	return batch, devices, raw, nil
}

func decodeAgentMetricBatch(r *http.Request) (agentMetricBatch, []agentMetricInput, error) {
	var batch agentMetricBatch
	if err := decodeJSONBody(r, &batch); err != nil {
		return batch, nil, err
	}
	if len(batch.Metrics) > maxAgentMetricBatch {
		return batch, nil, fmt.Errorf("metric batch exceeds %d entries", maxAgentMetricBatch)
	}
	metrics := make([]agentMetricInput, 0, len(batch.Metrics))
	for _, item := range batch.Metrics {
		var metric agentMetricInput
		if _, err := decodeAgentTelemetryItem(item, &metric); err != nil {
			return batch, nil, err
		}
		if err := validateAgentMetric(metric); err != nil {
			return batch, nil, err
		}
		metrics = append(metrics, metric)
	}
	return batch, metrics, nil
}
