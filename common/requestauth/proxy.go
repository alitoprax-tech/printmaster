// Package requestauth carries authenticated identities across in-process proxy dispatch.
// HTTP headers alone must never establish a trusted principal.
package requestauth

import "context"

type proxyKey struct{}

type ProxyPrincipal struct {
	Username string
	Role     string
}

// WithProxyPrincipal is only called by the authenticated server WebSocket dispatcher.
func WithProxyPrincipal(ctx context.Context, username, role string) context.Context {
	return context.WithValue(ctx, proxyKey{}, ProxyPrincipal{Username: username, Role: role})
}

func ProxyPrincipalFromContext(ctx context.Context) (ProxyPrincipal, bool) {
	p, ok := ctx.Value(proxyKey{}).(ProxyPrincipal)
	if !ok || p.Username == "" {
		return ProxyPrincipal{}, false
	}
	switch p.Role {
	case "admin", "operator", "viewer":
		return p, true
	default:
		return ProxyPrincipal{}, false
	}
}
