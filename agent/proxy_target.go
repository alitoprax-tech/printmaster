package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// buildPrinterProxyURL builds a URL for a literal printer IP.  Printer
// addresses are stored as IPs because allowing an arbitrary hostname here
// would make the proxy vulnerable to DNS rebinding between validation and the
// actual request.
func buildPrinterProxyURL(scheme, ip, port string) string {
	host := strings.Trim(strings.TrimSpace(ip), "[]")
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return (&url.URL{Scheme: scheme, Host: host}).String()
}

// validatePrinterProxyTarget validates and canonicalizes a printer web UI
// target.  The target must use the exact literal IP recorded for the device;
// hostnames are rejected so a later DNS lookup cannot redirect the agent to an
// unrelated internal service.  Loopback, unspecified, multicast, and
// link-local addresses are never valid network printer targets.  RFC1918 and
// other global-unicast addresses remain valid because customer printers are
// normally on private networks.
func validatePrinterProxyTarget(rawURL, deviceIP string) (*url.URL, error) {
	deviceIP = strings.TrimSpace(strings.Trim(deviceIP, "[]"))
	expectedIP := net.ParseIP(deviceIP)
	if expectedIP == nil || strings.Contains(deviceIP, "%") {
		return nil, fmt.Errorf("device IP must be a literal IP address")
	}
	if !isUsablePrinterIP(expectedIP) {
		return nil, fmt.Errorf("device IP is not a usable unicast address")
	}

	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid printer target URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("printer target scheme must be http or https")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("printer target must include a host")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("printer target userinfo is not allowed")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("printer target query and fragment are not allowed")
	}

	hostname := parsed.Hostname()
	targetIP := net.ParseIP(strings.Trim(hostname, "[]"))
	if targetIP == nil || !targetIP.Equal(expectedIP) {
		return nil, fmt.Errorf("printer target host must match the recorded device IP")
	}
	if !isUsablePrinterIP(targetIP) {
		return nil, fmt.Errorf("printer target IP is not a usable unicast address")
	}

	port := parsed.Port()
	portNumber := 80
	if parsed.Scheme == "https" {
		portNumber = 443
	}
	if port != "" {
		portNumber, err = strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return nil, fmt.Errorf("printer target port is invalid")
		}
	}
	if !printerProxyPortAllowed(portNumber) {
		return nil, fmt.Errorf("printer target port is not allowed")
	}

	// Replace the original host with a canonical literal IP.  This makes the
	// subsequent dial deterministic even when the original URL used unusual
	// casing or IPv6 formatting.
	parsed.Host = targetIP.String()
	if port != "" {
		parsed.Host = net.JoinHostPort(targetIP.String(), port)
	} else if targetIP.To4() == nil {
		parsed.Host = "[" + targetIP.String() + "]"
	}
	parsed.RawPath = ""
	return parsed, nil
}

// Additional ports are a local Agent operator decision; the server and a
// printer's reported URL cannot expand this allowlist. Invalid configuration
// does not permit any extra port.
func printerProxyPortAllowed(port int) bool {
	if port == 80 || port == 443 {
		return true
	}
	for _, entry := range strings.Split(os.Getenv("PRINTMASTER_PRINTER_PROXY_PORTS"), ",") {
		value, err := strconv.Atoi(strings.TrimSpace(entry))
		if err == nil && value >= 1 && value <= 65535 && value == port {
			return true
		}
	}
	return false
}

// The final TCP destination is checked again at dial time. In particular a
// transport must not follow a request to another IP or an unexpected port.
func validatePrinterProxyDial(address string, target *url.URL) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid printer dial address")
	}
	actual := net.ParseIP(strings.Trim(host, "[]"))
	expected := net.ParseIP(target.Hostname())
	if actual == nil || expected == nil || !actual.Equal(expected) {
		return fmt.Errorf("printer dial destination changed")
	}
	value, err := strconv.Atoi(port)
	if err != nil || !printerProxyPortAllowed(value) {
		return fmt.Errorf("printer dial port is not allowed")
	}
	expectedPort := target.Port()
	if expectedPort == "" {
		expectedPort = "80"
		if target.Scheme == "https" {
			expectedPort = "443"
		}
	}
	if port != expectedPort {
		return fmt.Errorf("printer dial port changed")
	}
	return nil
}

// A printer redirect may change the path/query within the same origin only.
// A browser must never be sent to a different LAN host, protocol or port.
func validatePrinterProxyRedirect(base *url.URL, location, deviceIP string) (*url.URL, error) {
	ref, err := url.Parse(location)
	if err != nil || ref.User != nil {
		return nil, fmt.Errorf("invalid printer redirect")
	}
	resolved := base.ResolveReference(ref)
	if resolved.Scheme != base.Scheme || resolved.Host != base.Host {
		return nil, fmt.Errorf("printer redirect leaves its allowed target")
	}
	if _, err := validatePrinterProxyTarget(resolved.Scheme+"://"+resolved.Host+resolved.Path, deviceIP); err != nil {
		return nil, fmt.Errorf("printer redirect leaves its allowed target")
	}
	return ref, nil
}

func isUsablePrinterIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}
