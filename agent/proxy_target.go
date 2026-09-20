package main

import (
	"fmt"
	"net"
	"net/url"
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
	if port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return nil, fmt.Errorf("printer target port is invalid")
		}
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

func isUsablePrinterIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}
