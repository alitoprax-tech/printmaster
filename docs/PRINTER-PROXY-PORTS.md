# Printer proxy network boundary (P0-05)

The Agent accepts a printer web UI only at its recorded literal device IP. The
default TCP ports are 80 and 443. A local Agent operator can explicitly add
vendor ports with `PRINTMASTER_PRINTER_PROXY_PORTS=8443,8080` in the Agent
service environment. Do not expose this setting through a server-supplied job
or device metadata. An invalid entry grants no additional port.

The Agent validates the stored target before probing, verifies the final TCP
dial address against that target, and rejects redirects that change scheme,
host, or port. A printer UI that needs another port must be configured on its
own Agent host. The three-origin deployment described in
`docs/TRUST-BOUNDARIES.md` remains required for browser isolation.

Proxy tickets and five-minute sessions bind the user, tenant, Agent and
device (where applicable). The server rechecks that binding against storage
at redemption and on each request; deleting or moving the resource invalidates
the session. Tests cover compressed-response expansion, bounded stream size,
unresponsive Agent timeout, and sandboxing printer HTML with printer cookies
discarded. A broader review of vendor login and local Agent UI behavior is
still required before public deployment.
