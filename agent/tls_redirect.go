package main

import (
	"bufio"
	"fmt"
	"html"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	httpRedirectReadTimeout    = 5 * time.Second
	httpRedirectMaxHeaderBytes = 16 << 10
	httpRedirectMaxWorkers     = 64
)

// httpRedirectListener wraps a net.Listener to detect plain HTTP requests
// on a TLS port and redirect them to HTTPS instead of showing a TLS error.
type httpRedirectListener struct {
	net.Listener
	httpsPort     string
	redirectSlots chan struct{}
}

// newHTTPRedirectListener creates a listener that detects HTTP on HTTPS port
// and sends a redirect response instead of a TLS handshake error.
func newHTTPRedirectListener(inner net.Listener, httpsPort string) net.Listener {
	if port := parsedRedirectPort(httpsPort); port > 0 {
		httpsPort = strconv.Itoa(port)
	} else {
		// The listener normally receives a validated configured port. Keep a
		// malformed value from ever reaching a reflected Location header.
		httpsPort = "443"
	}
	return &httpRedirectListener{
		Listener:      inner,
		httpsPort:     httpsPort,
		redirectSlots: make(chan struct{}, httpRedirectMaxWorkers),
	}
}

// Accept waits for and returns the next connection to the listener.
// If the connection starts with plain HTTP, it sends a redirect and closes.
func (l *httpRedirectListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		// Peek at the first byte without allowing an idle plaintext connection to
		// starve the TLS listener.
		peekedConn := &peekConn{Conn: conn, reader: bufio.NewReader(conn)}
		if err := conn.SetReadDeadline(time.Now().Add(httpRedirectReadTimeout)); err != nil {
			_ = conn.Close()
			continue
		}
		firstByte, err := peekedConn.reader.Peek(1)
		if err != nil {
			_ = conn.Close()
			continue
		}

		// TLS ClientHello starts with 0x16. Replay the peeked byte to the TLS
		// stack and clear the temporary deadline.
		if firstByte[0] == 0x16 {
			_ = conn.SetReadDeadline(time.Time{})
			return peekedConn, nil
		}

		// Plain HTTP request on HTTPS port - send a bounded redirect without
		// spawning an unbounded goroutine for every connection.
		if l.redirectSlots == nil {
			l.redirectSlots = make(chan struct{}, httpRedirectMaxWorkers)
		}
		select {
		case l.redirectSlots <- struct{}{}:
			go func() {
				defer func() { <-l.redirectSlots }()
				l.handleHTTPRedirect(peekedConn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

// handleHTTPRedirect reads the HTTP request and sends a redirect to HTTPS.
func (l *httpRedirectListener) handleHTTPRedirect(conn *peekConn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(httpRedirectReadTimeout))
	remaining := httpRedirectMaxHeaderBytes

	line, err := readRedirectLine(conn.reader, &remaining)
	if err != nil {
		return
	}

	// Parse minimal request info (e.g., "GET /path HTTP/1.1").
	var method, path string
	_, _ = fmt.Sscanf(line, "%s %s", &method, &path)
	if path == "" {
		path = "/"
	}
	path = sanitizeRedirectPath(path)

	// Determine the host from Host header or use localhost. Host and path are
	// validated before they are reflected into an HTTP header or HTML body.
	host := fmt.Sprintf("localhost:%s", l.httpsPort)
	for {
		headerLine, readErr := readRedirectLine(conn.reader, &remaining)
		if readErr != nil || headerLine == "\r\n" || headerLine == "\n" {
			break
		}
		if len(headerLine) > 5 && strings.EqualFold(headerLine[:5], "Host:") {
			host = sanitizeRedirectHost(headerLine[5:], l.httpsPort)
			break
		}
	}

	redirectURL := fmt.Sprintf("https://%s%s", host, path)
	redirectHTMLURL := html.EscapeString(redirectURL)
	body := fmt.Sprintf(
		"<html><head><title>Redirecting</title></head><body>"+
			"<h1>Moved Permanently</h1>"+
			"<p>This server requires HTTPS. Redirecting to <a href=\"%s\">%s</a></p>"+
			"</body></html>",
		redirectHTMLURL, redirectHTMLURL,
	)
	response := fmt.Sprintf(
		"HTTP/1.1 301 Moved Permanently\r\n"+
			"Location: %s\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		redirectURL, len(body), body,
	)
	_, _ = conn.Write([]byte(response))

	if appLogger != nil {
		appLogger.Debug("Redirected HTTP request to HTTPS",
			"remote_addr", conn.RemoteAddr().String(),
			"path", path,
			"redirect_url", redirectURL)
	}
}

// readRedirectLine reads one HTTP request line while enforcing the aggregate
// request-header budget used by the custom plaintext redirect path.
func readRedirectLine(reader *bufio.Reader, remaining *int) (string, error) {
	if reader == nil || remaining == nil || *remaining <= 0 {
		return "", bufio.ErrBufferFull
	}
	var line []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(part) > *remaining {
			return "", bufio.ErrBufferFull
		}
		*remaining -= len(part)
		line = append(line, part...)
		if err == bufio.ErrBufferFull {
			if *remaining == 0 {
				return "", bufio.ErrBufferFull
			}
			continue
		}
		if err != nil {
			return "", err
		}
		return string(line), nil
	}
}

// sanitizeRedirectPath validates the request target before it is reflected in
// both the Location header and the HTML response.
func sanitizeRedirectPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || len(path) > 8192 || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\r\n") {
		return "/"
	}
	return path
}

// sanitizeRedirectHost accepts a normal Host header (DNS name or IP, with an
// optional numeric port) and returns a safe host:port for an HTTPS redirect.
func sanitizeRedirectHost(raw, httpsPort string) string {
	fallback := fmt.Sprintf("localhost:%s", httpsPort)
	host := strings.TrimSpace(raw)
	if host == "" || len(host) > 255 || strings.ContainsAny(host, "\r\n\t /?#@") {
		return fallback
	}

	name := host
	port := parsedRedirectPort(httpsPort)
	if strings.HasPrefix(host, "[") {
		parsedHost, parsedPort, err := net.SplitHostPort(host)
		if err != nil || net.ParseIP(parsedHost) == nil {
			return fallback
		}
		name = parsedHost
		port = parsedPortNumber(parsedPort)
		if port <= 0 {
			return fallback
		}
	} else if strings.Count(host, ":") == 1 {
		parsedHost, parsedPort, err := net.SplitHostPort(host)
		if err != nil || !validRedirectHostname(parsedHost) {
			return fallback
		}
		name = parsedHost
		port = parsedPortNumber(parsedPort)
		if port <= 0 {
			return fallback
		}
	} else if strings.Count(host, ":") > 1 {
		// Bare IPv6 literals are not valid Host header syntax; require brackets.
		return fallback
	} else if net.ParseIP(host) != nil {
		name = host
	} else if !validRedirectHostname(host) {
		return fallback
	}
	if port <= 0 {
		return fallback
	}
	return net.JoinHostPort(name, strconv.Itoa(port))
}

func parsedRedirectPort(raw string) int {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

func parsedPortNumber(raw string) int {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

func validRedirectHostname(host string) bool {
	if host == "" || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

// peekConn wraps a net.Conn with a buffered reader to allow peeking.
type peekConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read reads data from the connection, using buffered data first.
func (c *peekConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// WriteTo implements io.WriterTo for efficient copying.
func (c *peekConn) WriteTo(w io.Writer) (int64, error) {
	return c.reader.WriteTo(w)
}
