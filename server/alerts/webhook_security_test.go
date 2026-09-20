package alerts

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
)

func TestWebhookDialPinsPublicAddressAndRejectsRebinding(t *testing.T) {
	for _, tc := range []struct {
		addresses []string
		wantDial  bool
	}{
		{[]string{"8.8.8.8"}, true},
		{[]string{"8.8.8.8", "127.0.0.1"}, false},
		{[]string{"169.254.169.254"}, false},
		{[]string{"100.100.100.200"}, false},
		{[]string{"::ffff:127.0.0.1"}, false},
		{[]string{"0.0.0.0"}, false},
		{nil, false},
	} {
		calls := 0
		lookup := func(context.Context, string) ([]net.IPAddr, error) {
			var ips []net.IPAddr
			for _, value := range tc.addresses {
				ips = append(ips, net.IPAddr{IP: net.ParseIP(value)})
			}
			return ips, nil
		}
		dial := func(_ context.Context, _ string, address string) (net.Conn, error) {
			calls++
			if address != "8.8.8.8:443" {
				t.Fatalf("dial did not use validated IP: %s", address)
			}
			return nil, nil
		}
		_, err := dialPublicWebhook(context.Background(), "tcp", "webhook.example:443", lookup, dial)
		if tc.wantDial {
			if calls != 1 || err != nil {
				t.Fatal("valid public destination rejected")
			}
		} else if calls != 0 || err == nil {
			t.Fatalf("unsafe destination accepted: %v", tc.addresses)
		}
	}
	_, err := dialPublicWebhook(context.Background(), "tcp", "missing.example:443", func(context.Context, string) ([]net.IPAddr, error) { return nil, fmt.Errorf("DNS failed") }, func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dial after DNS failure")
		return nil, nil
	})
	if err == nil {
		t.Fatal("DNS failure was accepted")
	}
	if newWebhookHTTPClient().CheckRedirect(&http.Request{}, nil) == nil {
		t.Fatal("redirect policy is permissive")
	}
}
