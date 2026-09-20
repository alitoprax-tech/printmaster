package vendor

import "testing"

func TestConfiguredEpsonRemoteCommunityFailsClosed(t *testing.T) {
	t.Setenv("SNMP_VERSION", "3")
	t.Setenv("SNMP_COMMUNITY", "public")
	if _, err := configuredEpsonRemoteCommunity(); err == nil {
		t.Fatal("expected SNMPv3 to be rejected by the v1/v2c-only remote helper")
	}

	t.Setenv("SNMP_VERSION", "2c")
	t.Setenv("SNMP_COMMUNITY", "")
	if _, err := configuredEpsonRemoteCommunity(); err == nil {
		t.Fatal("expected missing community to fail closed")
	}

	for _, value := range []string{" leading", "trailing ", "line\nbreak"} {
		t.Setenv("SNMP_COMMUNITY", value)
		if _, err := configuredEpsonRemoteCommunity(); err == nil {
			t.Errorf("expected unsafe community %q to be rejected", value)
		}
	}

	t.Setenv("SNMP_COMMUNITY", "customer-snmp-2026")
	community, err := configuredEpsonRemoteCommunity()
	if err != nil || community != "customer-snmp-2026" {
		t.Fatalf("valid community rejected: got %q err=%v", community, err)
	}
}

func TestNewVendorSNMPClientRequiresCommunity(t *testing.T) {
	if _, err := NewVendorSNMPClient("127.0.0.1", "", 1); err == nil {
		t.Fatal("expected empty community to fail before any network connection")
	}
}
