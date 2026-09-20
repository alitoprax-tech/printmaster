// Package smtpclient sends mail over a single DNS-pinned connection.
package smtpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	stdsmtp "net/smtp"
	"strconv"
	"strings"
	"time"
)

type lookupAddresses func(context.Context, string) ([]net.IPAddr, error)
type dialAddress func(context.Context, string, string) (net.Conn, error)

// Send resolves the SMTP hostname once, validates all answers when
// rejectPrivate is true, and dials a numeric address.  The original hostname
// is retained for EHLO, STARTTLS SNI, and authentication, but it is never
// resolved again by the dial path.
func Send(ctx context.Context, host string, port int, username, password, from string, recipients []string, message []byte, rejectPrivate bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return sendWithResolvers(ctx, host, port, username, password, from, recipients, message, rejectPrivate, net.DefaultResolver.LookupIPAddr, dialer.DialContext)
}

func sendWithResolvers(ctx context.Context, host string, port int, username, password, from string, recipients []string, message []byte, rejectPrivate bool, lookup lookupAddresses, dial dialAddress) error {
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, "\r\n/@") {
		return fmt.Errorf("invalid SMTP host")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid SMTP port")
	}
	if strings.TrimSpace(from) == "" || len(recipients) == 0 {
		return fmt.Errorf("SMTP sender and at least one recipient are required")
	}
	if lookup == nil || dial == nil {
		return fmt.Errorf("SMTP transport is not configured")
	}

	addresses, err := lookup(ctx, strings.Trim(host, "[]"))
	if err != nil {
		return fmt.Errorf("SMTP host lookup failed: %w", err)
	}
	if len(addresses) == 0 {
		return fmt.Errorf("SMTP host has no addresses")
	}

	var lastErr error
	for _, address := range addresses {
		if address.IP == nil || address.Zone != "" {
			lastErr = fmt.Errorf("SMTP host returned an invalid address")
			continue
		}
		if rejectPrivate && isNonPublic(address.IP) {
			return fmt.Errorf("SMTP destination cannot target private/internal networks")
		}
		conn, err := dial(ctx, "tcp", net.JoinHostPort(address.IP.String(), strconv.Itoa(port)))
		if err != nil {
			lastErr = err
			continue
		}
		if err := sendOnConnection(ctx, conn, host, username, password, from, recipients, message); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("SMTP connection failed")
	}
	return lastErr
}

func sendOnConnection(ctx context.Context, conn net.Conn, host, username, password, from string, recipients []string, message []byte) error {
	defer conn.Close()
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	client, err := stdsmtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP handshake failed: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}); err != nil {
			return fmt.Errorf("SMTP STARTTLS failed: %w", err)
		}
	} else if username != "" {
		// Never send configured credentials over an unauthenticated SMTP
		// connection.  Port 587 and tenant-specific alert channels commonly
		// carry passwords, so opportunistic plaintext AUTH is not acceptable.
		return fmt.Errorf("SMTP server does not support STARTTLS; refusing authenticated cleartext SMTP")
	}
	if username != "" {
		if err := client.Auth(stdsmtp.PlainAuth("", username, password, host)); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("SMTP RCPT TO failed: %w", err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA failed: %w", err)
	}
	if _, err := io.Copy(writer, bytes.NewReader(message)); err != nil {
		_ = writer.Close()
		return fmt.Errorf("SMTP message write failed: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("SMTP message close failed: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("SMTP QUIT failed: %w", err)
	}
	return nil
}

func isNonPublic(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}
	// RFC6598 and documentation/test ranges are not routable public SMTP
	// destinations even though net.IP.IsGlobalUnicast reports true for them.
	for _, cidr := range []string{
		"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "64:ff9b::/96",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
