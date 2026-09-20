package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	wscommon "printmaster/common/ws"
	"strings"
)

var errProxyBodyTooLarge = errors.New("proxy body exceeds configured limit")

func writeProxyBodyError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	message := "failed to read request body"
	if errors.Is(err, errProxyBodyTooLarge) {
		status = http.StatusRequestEntityTooLarge
		message = "proxy request body too large"
	}
	http.Error(w, message, status)
}

func browserProxyEnabled() bool {
	return serverConfig != nil && serverConfig.Server.BrowserProxyEnabled
}

func readBoundedProxyBody(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, errProxyBodyTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errProxyBodyTooLarge
	}
	return body, nil
}

func decompressProxyGzip(body []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	decompressed, readErr := readBoundedProxyBody(gr, maxProxyDecompressedBodySize)
	closeErr := gr.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return decompressed, nil
}

func copySafeProxyResponseHeaders(dst http.Header, raw interface{}) {
	headers, ok := raw.(map[string]interface{})
	if !ok {
		return
	}
	// Agent/proxy responses are untrusted. Keep this intentionally small.
	allowed := map[string]bool{
		"content-type": true, "content-encoding": true, "etag": true,
		"last-modified": true, "accept-ranges": true,
	}
	for k, v := range headers {
		if !allowed[strings.ToLower(k)] {
			continue
		}
		value, ok := v.(string)
		if !ok || strings.ContainsAny(value, "\r\n") {
			continue
		}
		dst.Set(k, value)
	}
}

type pendingProxy struct {
	agentID    string
	connection *wscommon.Conn
	responses  chan wscommon.Message
}

func registerProxyRequest(agentID string, responses chan wscommon.Message) string {
	id := rand.Text()
	conn, _ := getAgentWSConnection(agentID)
	proxyRequestsLock.Lock()
	proxyRequests[id] = pendingProxy{agentID: agentID, connection: conn, responses: responses}
	proxyRequestsLock.Unlock()
	return id
}

func takeProxyChannel(agentID string, conn *wscommon.Conn, id string, remove bool) (chan wscommon.Message, bool) {
	proxyRequestsLock.Lock()
	defer proxyRequestsLock.Unlock()
	p, ok := proxyRequests[id]
	if !ok || conn == nil || p.connection != conn || p.agentID != agentID {
		return nil, false
	}
	if remove {
		delete(proxyRequests, id)
	}
	return p.responses, true
}

func trustedProxyHeaders(r *http.Request) map[string]string {
	h := make(map[string]string)
	for k, v := range r.Header {
		key := strings.ToLower(k)
		if strings.HasPrefix(key, "x-printmaster-") || key == "authorization" || key == "cookie" || key == "proxy-authorization" {
			continue
		}
		if len(v) > 0 {
			h[k] = v[0]
		}
	}
	if p := getPrincipal(r); p != nil && p.User != nil {
		h["X-PrintMaster-User"] = p.User.Username
		h["X-PrintMaster-Role"] = string(p.Role)
	}
	return h
}
