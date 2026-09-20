package agent

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func TestConfiguredSNMPTrapCommunityRequiresExplicitSafeValue(t *testing.T) {
	t.Setenv("SNMP_TRAP_COMMUNITY", "")
	if _, err := configuredSNMPTrapCommunity(); err == nil {
		t.Fatal("expected an unset trap community to fail closed")
	}

	valid := "customer-traps-2026"
	t.Setenv("SNMP_TRAP_COMMUNITY", valid)
	got, err := configuredSNMPTrapCommunity()
	if err != nil || got != valid {
		t.Fatalf("valid trap community rejected: got %q err=%v", got, err)
	}

	for _, value := range []string{" leading", "trailing ", "line\nbreak", "tab\tvalue", strings.Repeat("x", maxSNMPTrapCommunityLength+1)} {
		t.Setenv("SNMP_TRAP_COMMUNITY", value)
		if _, err := configuredSNMPTrapCommunity(); err == nil {
			t.Errorf("expected unsafe trap community %q to be rejected", value)
		}
	}
}

func TestSNMPTrapCommunityMatchesConstantTimeValue(t *testing.T) {
	if !snmpTrapCommunityMatches("secret", "secret") {
		t.Fatal("expected equal communities to match")
	}
	for _, value := range []string{"Secret", "secret ", "secret-longer", ""} {
		if snmpTrapCommunityMatches("secret", value) {
			t.Errorf("unexpected community match for %q", value)
		}
	}
}

func TestHandleTrapRejectsUnusableSources(t *testing.T) {
	packet := &gosnmp.SnmpPacket{}
	var accepted []string
	enqueue := func(ip string) bool {
		accepted = append(accepted, ip)
		return true
	}

	for _, ip := range []string{"127.0.0.1", "169.254.1.10", "224.0.0.1", "0.0.0.0"} {
		handleTrap(packet, &net.UDPAddr{IP: net.ParseIP(ip)}, enqueue)
	}
	handleTrap(packet, &net.UDPAddr{IP: net.ParseIP("10.20.30.40")}, enqueue)

	if len(accepted) != 1 || accepted[0] != "10.20.30.40" {
		t.Fatalf("unexpected trap source filtering result: %#v", accepted)
	}
}

func TestStartSNMPTrapListenerStopsWhenContextCanceled(t *testing.T) {
	t.Setenv("SNMP_TRAP_COMMUNITY", "customer-traps-2026")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Skipf("UDP socket unavailable in test environment: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	result := make(chan error, 1)
	go func() {
		result <- StartSNMPTrapListener(ctx, func(string) bool { return true }, uint16(port))
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("trap listener failed during shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("trap listener did not stop after context cancellation")
	}
}
