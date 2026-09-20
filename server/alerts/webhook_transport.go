package alerts

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

type lookupAddresses func(context.Context, string) ([]net.IPAddr, error)
type dialAddress func(context.Context, string, string) (net.Conn, error)

// Resolve once, validate all answers, and connect to the validated numeric address.
// No HTTP proxy or second DNS resolution may change the destination afterwards.
func dialPublicWebhook(ctx context.Context, network, address string, lookup lookupAddresses, dial dialAddress) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("webhook DNS lookup failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("webhook hostname has no addresses")
	}
	for _, ip := range ips {
		if ip.Zone != "" || isPrivateIP(ip.IP) {
			return nil, fmt.Errorf("webhook destination is not a public address")
		}
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := dial(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func newWebhookHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if allowTestWebhooks {
			return dialer.DialContext(ctx, network, address)
		}
		return dialPublicWebhook(ctx, network, address, net.DefaultResolver.LookupIPAddr, dialer.DialContext)
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		Transport:     transport,
		CheckRedirect: func(r *http.Request, via []*http.Request) error { return fmt.Errorf("webhook redirects are disabled") },
	}
}
