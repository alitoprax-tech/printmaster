package alerts

import "testing"

func TestChannelSupportsRule(t *testing.T) {
	tests := []struct {
		name           string
		ruleTenants    []string
		channelTenants []string
		allowGlobal    bool
		want           bool
	}{
		{name: "global rule global channel", want: true},
		{name: "global rule tenant channel", channelTenants: []string{"tenant-a"}, allowGlobal: true, want: false},
		{name: "tenant rule own channel", ruleTenants: []string{"tenant-a"}, channelTenants: []string{"tenant-a"}, want: true},
		{name: "tenant rule missing tenant", ruleTenants: []string{"tenant-a", "tenant-b"}, channelTenants: []string{"tenant-a"}, want: false},
		{name: "admin may use global channel", ruleTenants: []string{"tenant-a"}, allowGlobal: true, want: true},
		{name: "operator may not use global channel", ruleTenants: []string{"tenant-a"}, want: false},
		{name: "shared channel covers rule", ruleTenants: []string{"tenant-a"}, channelTenants: []string{"tenant-a", "tenant-b"}, want: true},
		{name: "blank IDs ignored", ruleTenants: []string{" tenant-a ", ""}, channelTenants: []string{"tenant-a"}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := channelSupportsRule(tc.ruleTenants, tc.channelTenants, tc.allowGlobal); got != tc.want {
				t.Fatalf("channelSupportsRule() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAlertTenantBoundaries(t *testing.T) {
	tests := []struct {
		name                  string
		rule                  []string
		channel               []string
		alert                 string
		wantRule, wantChannel bool
	}{
		{name: "global", alert: "tenant-a", wantRule: true, wantChannel: true},
		{name: "matching tenant", rule: []string{"tenant-a"}, channel: []string{"tenant-a"}, alert: "tenant-a", wantRule: true, wantChannel: true},
		{name: "foreign tenant", rule: []string{"tenant-a"}, channel: []string{"tenant-a"}, alert: "tenant-b", wantRule: false, wantChannel: false},
		{name: "empty alert tenant", rule: []string{"tenant-a"}, channel: []string{"tenant-a"}, wantRule: false, wantChannel: false},
		{name: "global channel", channel: nil, alert: "tenant-b", wantRule: true, wantChannel: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tenantScopeAllowsAlert(tc.rule, tc.alert); got != tc.wantRule {
				t.Fatalf("tenantScopeAllowsAlert() = %v, want %v", got, tc.wantRule)
			}
			if got := channelAllowsAlert(tc.channel, tc.alert); got != tc.wantChannel {
				t.Fatalf("channelAllowsAlert() = %v, want %v", got, tc.wantChannel)
			}
		})
	}
}
