package agent

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

const (
	maxSNMPTrapCommunityLength = 256
	maxSNMPTrapSources         = 4096
)

// configuredSNMPTrapCommunity returns the explicitly configured community for
// incoming v1/v2c traps.  The trap listener is an optional network entry point;
// accepting the historical SNMP "public" default would let any host that can
// reach UDP/162 trigger discovery work.  An explicit value is therefore
// required and is never inherited from SNMP_COMMUNITY.
func configuredSNMPTrapCommunity() (string, error) {
	community, ok := os.LookupEnv("SNMP_TRAP_COMMUNITY")
	if !ok || community == "" {
		return "", fmt.Errorf("SNMP_TRAP_COMMUNITY must be set before enabling the SNMP trap listener")
	}
	if strings.TrimSpace(community) != community {
		return "", fmt.Errorf("SNMP_TRAP_COMMUNITY must not have leading or trailing whitespace")
	}
	if !utf8.ValidString(community) {
		return "", fmt.Errorf("SNMP_TRAP_COMMUNITY must be valid UTF-8")
	}
	if len([]byte(community)) > maxSNMPTrapCommunityLength {
		return "", fmt.Errorf("SNMP_TRAP_COMMUNITY exceeds %d bytes", maxSNMPTrapCommunityLength)
	}
	for _, r := range community {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("SNMP_TRAP_COMMUNITY contains a control character")
		}
	}
	return community, nil
}

func snmpTrapCommunityMatches(expected, actual string) bool {
	if expected == "" || len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func usableSNMPTrapSource(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsUnspecified() &&
		!ip.IsLoopback() && !ip.IsMulticast() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

// StartSNMPTrapListener listens for SNMP trap notifications on UDP port 162
// and enqueues discovered devices for SNMP enrichment. Runs until context is canceled.
//
// SNMP traps provide event-driven discovery when printers:
// - Power on or boot up
// - Change status (errors, warnings, ready)
// - Experience supply issues (toner low, paper jam, etc.)
//
// Note: Port 162 requires elevated privileges on most systems (admin/root)
func StartSNMPTrapListener(ctx context.Context, enqueue func(string) bool, port uint16) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if enqueue == nil {
		return fmt.Errorf("enqueue callback is required")
	}
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	trapCommunity, err := configuredSNMPTrapCommunity()
	if err != nil {
		return err
	}

	if port == 0 {
		port = 162 // Standard SNMP trap port
	}

	// Create trap listener
	tl := gosnmp.NewTrapListener()
	tl.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		if packet == nil || addr == nil || !snmpTrapCommunityMatches(trapCommunity, packet.Community) {
			// Do not log the supplied community.  Invalid packets are ignored so a
			// reachable UDP port cannot be used to fill logs or start discovery.
			return
		}
		handleTrap(packet, addr, enqueue)
	}

	// Set listener parameters on a fresh value.  gosnmp.Default contains a
	// mutex and must not be copied; mutating the package global would also race
	// with concurrent SNMP clients.
	tl.Params = &gosnmp.GoSNMP{
		Version:   gosnmp.Version2c, // Support both v1 and v2c
		Community: trapCommunity,
		Logger:    gosnmp.Default.Logger,
	}

	listenAddr := fmt.Sprintf("0.0.0.0:%d", port)

	Info(fmt.Sprintf("SNMP Traps: listening on %s (requires admin/root privileges)", listenAddr))

	// gosnmp.Listen blocks, so run it separately and close the socket when the
	// caller cancels.  Without this select the settings endpoint could never
	// stop the listener and UDP/162 would remain occupied until process exit.
	listenDone := make(chan error, 1)
	go func() { listenDone <- tl.Listen(listenAddr) }()
	defer tl.Close()

	select {
	case err := <-listenDone:
		if err != nil {
			return fmt.Errorf("failed to start trap listener: %w", err)
		}
		return nil
	case <-ctx.Done():
		Info("SNMP Traps: stopping listener")
		tl.Close()
		select {
		case err := <-listenDone:
			if err != nil {
				return fmt.Errorf("failed to stop trap listener: %w", err)
			}
		case <-time.After(5 * time.Second):
			return fmt.Errorf("timed out waiting for trap listener to stop")
		}
		return nil
	}
}

// handleTrap processes incoming SNMP trap notifications
func handleTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr, enqueue func(string) bool) {
	if packet == nil || addr == nil || enqueue == nil || !usableSNMPTrapSource(addr.IP) {
		return
	}

	ip := addr.IP.String()

	// Log trap reception
	trapType := "Generic"
	trapOID := ""

	// Extract trap information from PDUs
	for _, pdu := range packet.Variables {
		oidStr := pdu.Name

		// SNMPv2-MIB::snmpTrapOID (identifies the trap type)
		if oidStr == "1.3.6.1.6.3.1.1.4.1.0" {
			trapOID = fmt.Sprintf("%v", pdu.Value)

			// Common printer trap OIDs
			switch trapOID {
			case "1.3.6.1.2.1.43.18.2.0.1":
				trapType = "Printer Status Change"
			case "1.3.6.1.2.1.43.18.2.0.2":
				trapType = "Printer Warming Up"
			case "1.3.6.1.2.1.43.18.2.0.3":
				trapType = "Printer Supply Low"
			case "1.3.6.1.2.1.43.18.2.0.4":
				trapType = "Printer Cover Open"
			case "1.3.6.1.2.1.43.18.2.0.5":
				trapType = "Printer Configuration Change"
			default:
				trapType = "Printer Event"
			}
		}
	}

	Info(fmt.Sprintf("SNMP Trap: received %s from %s (OID: %s)", trapType, ip, trapOID))

	// Enqueue device IP for discovery
	if enqueue(ip) {
		Info(fmt.Sprintf("SNMP Trap: enqueued %s for discovery", ip))
	}
}

// StartSNMPTrapBrowser is a wrapper that handles the trap listener lifecycle
// with automatic restart on errors and throttling to prevent duplicate discoveries
func StartSNMPTrapBrowser(ctx context.Context, enqueue func(string) bool, seen map[string]time.Time, throttleWindow time.Duration) {
	if ctx == nil || enqueue == nil {
		return
	}
	if seen == nil {
		seen = make(map[string]time.Time)
	}
	if _, err := configuredSNMPTrapCommunity(); err != nil {
		Info("SNMP Trap Browser: " + err.Error())
		return
	}
	port := uint16(162) // Standard SNMP trap port

	// Try to start trap listener
	// Note: This will fail if not running with elevated privileges
	for {
		select {
		case <-ctx.Done():
			Info("SNMP Trap Browser: stopped")
			return
		default:
		}

		// Wrap enqueue with throttling logic
		throttledEnqueue := func(ip string) bool {
			now := time.Now()

			// Check if we've seen this IP recently
			if lastSeen, exists := seen[ip]; exists {
				if now.Sub(lastSeen) < throttleWindow {
					return false // Skip, too soon
				}
			}

			// Bound memory use if a compromised or noisy network sends traps from
			// many source addresses.  Remove stale entries first, then evict the
			// oldest entry if the cap is still reached.
			if len(seen) >= maxSNMPTrapSources {
				if throttleWindow > 0 {
					cutoff := now.Add(-throttleWindow)
					for key, timestamp := range seen {
						if timestamp.Before(cutoff) {
							delete(seen, key)
						}
					}
				}
				if len(seen) >= maxSNMPTrapSources {
					var oldestKey string
					var oldest time.Time
					for key, timestamp := range seen {
						if oldestKey == "" || timestamp.Before(oldest) {
							oldestKey, oldest = key, timestamp
						}
					}
					if oldestKey != "" {
						delete(seen, oldestKey)
					}
				}
			}

			// Update last seen time
			seen[ip] = now

			// Call original enqueue
			return enqueue(ip)
		}

		// Start trap listener (blocking)
		err := StartSNMPTrapListener(ctx, throttledEnqueue, port)

		if err != nil {
			Info("SNMP Trap Browser: " + err.Error())

			// Check if it's a permission error
			var netErr *net.OpError
			if errors.As(err, &netErr) {
				if netErr.Op == "listen" {
					Info("SNMP Trap Browser: Port 162 requires administrator/root privileges")
					Info("SNMP Trap Browser: Run as admin or disable trap monitoring")
					return // Don't retry if it's a permission issue
				}
			}
		}

		// If context was canceled, exit immediately
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Otherwise, wait a bit before retrying, while still honoring shutdown.
		Info("SNMP Trap Browser: restarting in 30 seconds...")
		timer := time.NewTimer(30 * time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-timer.C:
		}
	}
}
