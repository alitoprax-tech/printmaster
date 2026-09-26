# Production trust domains (P0-03)

Use three **distinct hostnames**, even though PrintMaster remains one binary:

| Origin | Purpose | Example |
| --- | --- | --- |
| Agent | Enrollment, mTLS HTTP and WebSocket, telemetry, Agent updates | `https://agents.example.com` |
| Admin | Login/OIDC, dashboard, management API | `https://admin.example.com` |
| Printer proxy | Customer printer and Agent web content only | `https://printer-proxy.example.com` |

The application checks the canonical request host and an explicit route matrix before any handler runs. Unknown hosts and cross-domain routes return 404. Administrative browser requests must have the admin origin; the Agent plane still authenticates with the P0-01 certificate. A session on the admin origin cannot authenticate an Agent request.

Example server configuration:

```toml
[server]
bind_address = "127.0.0.1"
behind_proxy = true
proxy_use_https = true
trusted_proxies = ["127.0.0.1/32"]
trust_domains_enabled = true
agent_host = "agents.example.com"
admin_host = "admin.example.com"
printer_proxy_host = "printer-proxy.example.com"
agent_external_url = "https://agents.example.com"
admin_external_url = "https://admin.example.com"
printer_proxy_external_url = "https://printer-proxy.example.com"
browser_proxy_enabled = true

[security]
agent_auth_mode = "mtls"
```

Replace loopback/trusted proxy addresses with the actual private interface and exact ingress IPs if the ingress is on another host. The backend port must be firewalled from the public Internet. All three external origins require valid TLS. A production non-loopback bind without the three trust domains fails at startup; loopback without origins remains available for local development. Wildcards and host reuse are rejected. An HTTP reverse-proxy backend cannot carry end-to-end Agent mTLS and is rejected when Agent authentication uses migration/mTLS mode.

Recommended ingress topology:

```text
Agent -- TLS + client certificate --> dedicated Agent TCP/TLS ingress --> PrintMaster TLS :9443
Browser -- HTTPS --> admin reverse proxy/CDN -- HTTPS --> PrintMaster TLS :9443
Browser -- HTTPS --> printer-proxy reverse proxy -- HTTPS --> PrintMaster TLS :9443
```

Route `agents.example.com` with TLS pass-through so PrintMaster receives the **actual** client certificate. Terminating Agent TLS at an ordinary CDN or HTTP proxy loses the certificate. Forwarding a client certificate as a header is not an authentication method in this configuration. Restrict access to the backend; strip incoming `X-Forwarded-Host` and `Forwarded` at the trusted admin/printer ingress, then set exactly one canonical `X-Forwarded-Host` and `X-Forwarded-Proto` value. Configure trusted proxy addresses explicitly. Untrusted peers cannot choose a trust domain through forwarded headers. Do not expose `agents.example.com` through the human admin CDN unless it preserves end-to-end client-certificate authentication.

Admin/OIDC/tenant-hint cookies use host-only `__Host-` names, `Secure`, `HttpOnly`, `Path=/`, and `SameSite=Lax`; no parent-domain cookie is set. Printer responses cannot copy `Set-Cookie` from printers. To open a printer UI, an authenticated admin browser sends `POST /api/v1/proxy-access` to the admin origin with `{"kind":"device","id":"SERIAL"}` (or `kind: "agent"` with its ID), then navigates to the returned printer-proxy URL within one minute. Existing dashboard GET links to the former admin-origin proxy path issue the same ticket and 303 redirect to the printer origin without rendering printer content on the admin origin. The one-use ticket is removed from the URL by a second 303 redirect; the proxy sets a host-only, resource-scoped, five-minute cookie. The existing authorization and tenant checks run on each proxy request. Browser proxying is disabled until explicitly enabled.

The printer proxy remains subject to P0-05 SSRF/pivot hardening. The ProgramData reparse/junction inspection versus ACL/file-operation TOCTOU note remains in the P0-07 Windows path-hardening backlog. Neither concern is resolved by trust-domain routing.
