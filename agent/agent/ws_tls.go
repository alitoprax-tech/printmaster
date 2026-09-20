package agent

import "crypto/tls"

// SetTLSConfig must be called before Start; the client owns a private clone.
func (ws *WSClient) SetTLSConfig(config *tls.Config) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if config != nil {
		clone := config.Clone()
		// Never inherit a caller's insecure override. Private PKI deployments
		// should provide RootCAs instead.
		clone.InsecureSkipVerify = false
		if clone.MinVersion == 0 {
			clone.MinVersion = tls.VersionTLS12
		}
		ws.tlsConfig = clone
	}
}
