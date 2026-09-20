# PrintMaster Security Hardening Implementation Plan

> Status: implementation backlog
>
> Threat model: **assume any customer PC running the Agent can become fully compromised.**
>
> Primary security objective: compromise of one Agent must remain isolated to that Agent/site and must not become a path to another tenant, the admin plane, the server OS, or the fleet-wide update channel.

## Instructions for Codex

Implement this plan **in task order** unless a task explicitly states that it can run independently.

For every task:

1. Read the current implementation before changing it.
2. Preserve existing behavior unless the security requirement explicitly changes it.
3. Add tests before considering the task complete.
4. Prefer small, reviewable commits/PRs. Do not combine unrelated P0 tasks into one large change.
5. Do not introduce remote shell, PowerShell, arbitrary process execution, arbitrary file write, or arbitrary TCP-connect capabilities.
6. Treat all Agent-provided data as untrusted even after successful authentication.
7. Authentication identity from the transport/server context is authoritative. Request-body `agent_id` or `tenant_id` must never override it.
8. Fail closed on security configuration errors.
9. Never log secrets, even at debug/trace level.
10. If a migration is required, implement a bounded compatibility period and a clear switch that disables legacy behavior.

Definition of Done for every security task:

- tests added and passing,
- failure paths tested,
- docs/config example updated,
- no secret added to logs,
- no tenant scope weakened,
- no new arbitrary execution/network primitive added.

---

# Execution order

## Phase 0 — production blockers

- [ ] P0-01 — Per-Agent mTLS identity and credential migration
- [ ] P0-02 — Windows secret storage + least-privilege service identity
- [ ] P0-03 — Split Agent/Admin/Printer-Proxy trust boundaries
- [ ] P0-04 — Strict HTTP/WSS Agent protocol, replay protection and quotas
- [ ] P0-05 — Printer proxy SSRF/pivot isolation
- [ ] P0-06 — Update trust independent of application server
- [ ] P0-07 — Privileged updater path/TOCTOU hardening
- [ ] P0-08 — Central secret redaction and audit hardening
- [ ] P0-09 — Tenant/device ownership and hostile telemetry validation
- [ ] P0-10 — Stored-XSS/CSP hardening

## Phase 1 — containment and continuous verification

- [ ] P1-01 — Agent quarantine/revocation/incident controls
- [ ] P1-02 — Security anomaly detection and telemetry abuse controls
- [ ] P1-03 — CI security gates, fuzzing and hostile-Agent test suite
- [ ] P1-04 — Release SBOM/provenance/dependency hardening
- [ ] P1-05 — Operational security runbooks and penetration-test checklist

---

# P0-01 — Replace persistent Agent bearer identity with per-Agent mTLS

## Goal

A database dump or copied Agent data directory must not expose credentials that allow an attacker to impersonate the fleet.

## Required design

Enrollment:

```text
one-time join token
    -> Agent generates private key locally
    -> Agent submits CSR
    -> server/Agent-CA issues Agent-specific client certificate
    -> subsequent HTTP/WSS connections authenticate with mTLS
```

The certificate identity must map to exactly:

```text
tenant_id + agent_id + credential_id
```

The request body is never authoritative for identity.

## Requirements

- Per-Agent client certificate.
- Short-lived/one-time enrollment token only for bootstrap.
- Agent private key never sent to server.
- Prefer non-exportable TPM-backed key on Windows.
- Certificate expiry + renewal/rotation.
- Revocation.
- Active WebSocket terminated when credential is revoked.
- Legacy bearer migration path.
- A production configuration switch must fully disable legacy bearer authentication.
- Agent CA trust and release/update-signing trust must be completely separate.

## Existing areas to inspect

- `server/websocket.go`
- `server/main.go`
- `server/storage/enrollment.go`
- `server/storage/base_store.go`
- `server/storage/postgres.go`
- `server/storage/sqlite.go`
- `agent/agent/ws_client.go`
- `agent/config.go`

## Existing risk to remove

Current storage/auth paths use a reusable Agent token and server storage performs token lookup. Long-lived raw Agent credentials must not remain in database rows after migration.

## Acceptance tests

- valid Agent certificate + matching Agent identity -> allowed,
- valid certificate + different Agent ID -> denied,
- valid certificate + different tenant -> denied,
- expired certificate -> denied,
- revoked certificate -> denied,
- deleted/revoked Agent active WSS -> disconnected,
- DB dump contains no reusable Agent private credential,
- legacy bearer -> controlled migration -> mTLS,
- migration mode off -> bearer Agent denied.

---

# P0-02 — Protect local secrets and reduce Windows Agent privilege

Depends on: P0-01 design.

## Goal

Stealing files from `C:\ProgramData\PrintMaster\` must not be enough to clone an Agent.

## Requirements

### Preferred identity storage

Windows:
- TPM-backed non-exportable private key where available.

Fallback:
- DPAPI bound to a dedicated PrintMaster service identity.
- Do not default to broad machine-wide secret scope when a service-scoped identity can be used.

### Service privilege

Normal collection/proxy Agent should use a dedicated low-privilege service identity where feasible.

Avoid LocalSystem for normal operation.

Define explicit ACLs for:
- Program Files binary directory,
- ProgramData Agent state,
- logs,
- update staging,
- local DB,
- configuration.

Updater privilege is handled separately in P0-07.

## Existing areas

- `agent/service.go`
- `agent/config.go`
- `agent/main.go`
- installer/service setup

## Acceptance tests

- plaintext long-lived Agent secret is not written to disk,
- unprivileged local user cannot read private Agent identity material,
- reinstall/upgrade preserves identity safely,
- corrupt/missing TPM/DPAPI state fails safely,
- service runs normal collection without SYSTEM where supported.

---

# P0-03 — Separate Agent ingress, human admin and printer proxy origins

Can begin in parallel with P0-01.

## Target trust domains

```text
agents.example.com
  Agent enrollment
  Agent mTLS API
  Agent WSS
  heartbeat
  devices/metrics
  update metadata/artifacts

admin.example.com
  login
  OIDC
  users
  tenants
  settings
  reports
  human admin API

printer-proxy.example.com
  isolated printer UI proxy only
```

## Requirements

- Agent host must not expose human admin routes.
- Admin cookie must not be scoped to Agent or printer-proxy origins.
- Printer-controlled HTML must never share the admin origin/session.
- Host/origin validation must be explicit.
- Production reverse-proxy examples must be documented.
- One-binary deployment may remain temporarily, but route middleware must preserve the three trust domains.

## Existing areas

- `server/main.go`
- `server/websocket.go`
- auth middleware
- deployment/reverse-proxy configuration

## Acceptance tests

- request to admin route on Agent hostname -> denied/not routed,
- Agent credential cannot authenticate to admin plane,
- admin cookie not sent to printer-proxy origin,
- wrong Host/Origin cases fail closed.

---

# P0-04 — Strict Agent protocol, replay protection and resource quotas

Depends on authenticated identity behavior from P0-01, but schema work can begin earlier.

## Goal

An authenticated but compromised Agent must not be able to feed arbitrary/unbounded structures to the server.

## HTTP telemetry

Replace loose payloads such as:

```go
[]map[string]interface{}
```

with typed request schemas.

Validate:
- max string lengths,
- enums,
- IP/MAC syntax,
- timestamps,
- numeric ranges,
- counter bounds,
- map/list sizes,
- unknown fields where practical.

Suggested initial safe ceilings:

```text
devices / batch <= 250
metrics / batch <= 500
request body <= route-specific cap
toner entries <= 32/device
```

Use server receive time separately from Agent report time.

## WebSocket

Use an explicit message allowlist.

Allowed examples:
- heartbeat,
- proxy response/chunk/end,
- update progress,
- job progress,
- device deleted,
- tightly defined server->Agent jobs.

Forbidden protocol capabilities:
- arbitrary shell,
- PowerShell,
- cmd,
- arbitrary process execution,
- arbitrary file read/write,
- arbitrary URL/TCP connect.

State-changing messages/jobs must include:
- `message_id` / `job_id`,
- `issued_at`,
- expiry,
- replay detection.

Reduce the generic 8 MiB model to message-specific limits.

Suggested starting points:
- heartbeat <= 16 KiB,
- normal command <= 32 KiB,
- bounded proxy streaming chunks,
- bounded outstanding requests per Agent.

## Quotas

Per Agent:
- request rate,
- bytes/minute,
- DB writes/minute,
- active WS count,
- active proxy sessions,
- concurrent jobs.

## Existing areas

- `common/ws/conn.go`
- `server/websocket.go`
- `server/main.go`
- `agent/agent/ws_client.go`

## Acceptance tests

Fuzz/test:
- malformed JSON,
- huge nested maps/lists,
- unknown fields,
- NaN/Inf,
- negative counters,
- impossible future timestamp,
- duplicate/replayed message ID,
- WS flood,
- oversized WS frame,
- reconnect storm.

One Agent must not create unbounded goroutines, memory growth or DB writes.

---

# P0-05 — Harden printer proxy against SSRF, LAN pivoting and hostile content

Depends on P0-03 for final browser isolation.

## Preserve existing good controls

Current code already includes useful concepts:
- literal printer IP,
- no hostname-based target,
- recorded device IP matching,
- DNS-rebinding avoidance,
- scheme checks,
- loopback/link-local/multicast rejection.

Do not regress these.

## Required changes

- Proxy from isolated `printer-proxy` origin.
- Short-lived proxy session bound to:
  - user,
  - tenant,
  - Agent,
  - device,
  - expiry.
- Validate target on **every request and every redirect**.
- Default allowed ports: 80/443.
- Extra vendor ports only by explicit configuration.
- Do not allow all ports 1-65535 by default.
- Block localhost, link-local, metadata, multicast, unspecified and non-device destinations.
- Bound:
  - headers,
  - body size,
  - total stream bytes,
  - redirect count,
  - request time,
  - decompression.
- Printer redirect to another IP/port -> denied unless explicitly validated as same allowed target.
- Printer HTML receives restrictive CSP/sandbox.
- Printer cookies cannot become admin cookies.
- Sensitive proxy headers stripped.

## Existing areas

- `agent/proxy_target.go`
- `agent/agent/ws_client.go`
- `server/proxy_security.go`
- `server/websocket.go`
- `server/main.go`

## Acceptance tests

- redirect to router/firewall IP -> blocked,
- redirect to 127.0.0.1 -> blocked,
- same printer IP port 22/445/3389 -> blocked by default,
- DNS rebinding attempt -> blocked,
- gzip bomb -> terminated,
- never-ending response -> timeout,
- malicious printer JavaScript -> cannot access admin session.

---

# P0-06 — Make release/update trust independent of application server

## Goal

Compromise of the PrintMaster web/application server alone must not permit arbitrary fleet-wide binary deployment.

## Trust model

The application server distributes artifacts but does not own the root private release-signing key.

Agent/updater pins a trusted public release root.

Verify before installation:
- signature,
- SHA-256,
- component,
- platform,
- architecture,
- version,
- artifact size,
- metadata expiry.

Add protection against:
- rollback,
- freeze,
- mix-and-match,
- wrong software/component,
- wrong platform,
- endless download.

Use TUF-like metadata semantics where appropriate.

Windows artifacts should also use Authenticode. Authenticode is defense-in-depth and does not replace application-level update trust.

## Key separation

Never reuse:
- Agent CA key,
- release/update signing key,
- application/session secrets.

Release private key must not live in normal server DB, application config or `.env`.

## Existing areas

- `agent/autoupdate/manager.go`
- `agent/autoupdate_worker.go`
- `server/selfupdate/*`
- release/build workflows

## Acceptance tests

- application server serves arbitrary unsigned EXE -> Agent refuses,
- signed manifest with mutated artifact -> refuses,
- valid artifact for wrong OS/arch/component -> refuses,
- stale/rollback metadata -> refuses according to policy,
- release-key rotation path tested.

---

# P0-07 — Harden privileged updater and Windows path handling

Depends on P0-06 trust metadata.

## Goal

The updater may run with elevated rights, therefore it must be a very small and narrowly scoped privilege boundary.

## Requirements

Updater accepts only:
- fixed PrintMaster update operation,
- trusted staged artifact,
- fixed install target.

Updater must never accept:
- arbitrary command,
- arbitrary executable path,
- arbitrary destination,
- arbitrary service name,
- generic file-copy operation exposed to the Agent.

Windows hardening:
- reject unsafe reparse points/junctions/symlinks,
- validate canonical parent directories,
- verify ownership/ACL expectations,
- avoid temp directories writable by untrusted users,
- re-open/revalidate artifact immediately before privileged replacement,
- defend against check/use races,
- rollback only to previously trusted PrintMaster binary.

## Acceptance tests

Windows integration tests:
- junction inserted after validation,
- staging directory replaced,
- target parent reparse point,
- alternate file substituted after hash check,
- untrusted ACL,
- rollback artifact tampered.

All must fail safely.

---

# P0-08 — Central secret redaction and audit integrity

Can be implemented early.

## Known current concern

Debug logging in WebSocket paths must not serialize the raw request header map because it can contain `Authorization`.

Response-header/body-preview diagnostics must also be treated as potentially sensitive.

## Requirements

Implement redaction centrally in the logging layer.

Always redact:
- Authorization,
- Proxy-Authorization,
- Cookie,
- Set-Cookie,
- Agent/join tokens,
- password reset/invite tokens,
- passwords,
- SNMP community,
- SNMPv3 secrets,
- device credentials,
- private keys.

Use non-secret credential fingerprints/IDs for correlation.

Sanitize attacker-controlled log fields:
- CR/LF/control characters,
- excessive length.

Audit events required for:
- Agent enrollment,
- credential rotation,
- revoke/quarantine,
- proxy start/end,
- scan,
- diagnostics,
- update deployment,
- user/role changes.

## Existing areas

- `server/websocket.go`
- `agent/agent/ws_client.go`
- logger packages
- audit helpers

## Acceptance tests

Inject unique canary secrets into:
- headers,
- payloads,
- error responses,
- debug paths.

Assert canary never appears in logs.

Test log-forging hostname/model payloads.

---

# P0-09 — Enforce tenant/device ownership and hostile telemetry validation

## Goal

Compromised Agent A cannot modify Tenant/Agent B data.

## Requirements

- Authenticated transport identity determines Agent/tenant.
- Request-body identity is informational only or removed.
- Device update and metric write must verify ownership.
- Same RFC1918 address may exist in many tenants.
- IP-only global lookups are forbidden for security-sensitive behavior.
- Prefer lookup keys including tenant/Agent/site context.
- Global serial assumptions must be reviewed where devices from different customers can collide.

All Agent-controlled data must have validation:
- serial,
- IP,
- MAC,
- manufacturer,
- model,
- hostname,
- firmware,
- location,
- description,
- status,
- raw_data,
- consumables.

Counters:
- no negative values,
- safe integer bounds,
- extreme jumps flagged as anomalous rather than blindly trusted for billing.

Time:
- retain `reported_at`,
- create/use trusted `received_at`.

## Existing areas

- `server/storage/base_store.go`
- ownership tests
- `server/main.go`

## Acceptance tests

- Agent A sends Agent B ID -> cannot write B,
- Agent A sends Tenant B ID -> cannot cross tenant,
- duplicate private IP in two tenants -> isolated correctly,
- cross-Agent serial overwrite -> denied,
- metric for device not owned by Agent -> denied,
- impossible counter/timestamp -> rejected or marked anomalous.

---

# P0-10 — Prevent telemetry-driven stored XSS and strengthen CSP

Can be implemented in parallel with P0-09.

## Threat

A compromised Agent can submit values such as:

```html
<img src=x onerror=...>
```

in model, hostname, status or other fields. The admin dashboard must never execute them.

## Requirements

- Inventory all Agent-controlled fields rendered in browser.
- Prefer DOM `textContent` / safe attribute APIs.
- Review every `innerHTML` and `insertAdjacentHTML` call receiving dynamic data.
- Use escaping only as a fallback; DOM construction is preferred.
- Add stored-XSS regression tests.
- Move away from CSP `script-src 'unsafe-inline'`.
- Prefer static scripts or nonce/hash policy.
- Printer HTML remains isolated under P0-05.

## Existing areas

- `server/web/app.js`
- `server/web/context-menu.js`
- `server/web/v2.js`
- server security-header middleware

## Acceptance tests

Stored payloads in:
- model,
- manufacturer,
- hostname,
- serial,
- location,
- description,
- status/alerts,
- raw-data-derived fields

render as text and never execute.

CSP tests must fail if an unexpected inline script path is introduced.

---

# P1-01 — Quarantine, revoke and incident containment

Depends on P0 identity/protocol work.

## States

At minimum:
- active,
- suspicious,
- quarantined,
- revoked.

## Quarantined Agent

May send limited heartbeat/security state but must not:
- open printer proxy,
- receive state-changing jobs,
- apply update,
- change config,
- create unbounded telemetry writes.

## Admin controls

Provide:
- isolate/quarantine,
- release quarantine,
- revoke identity.

All actions audited.

Revocation should terminate active connections.

---

# P1-02 — Detect compromised-Agent behavior

Server-side signals may include:
- repeated schema violations,
- replay attempts,
- connection replacement loops,
- excessive request rate,
- huge new device count,
- excessive unique serial/IP count,
- impossible counter jumps,
- proxy target violations,
- repeated authentication anomalies.

Severe signals may trigger configurable automatic quarantine.

False-positive-safe defaults required.

---

# P1-03 — CI security gates and hostile-Agent test harness

## CI

Add/standardize:
- `govulncheck`,
- CodeQL,
- `gosec` or equivalent,
- dependency review,
- npm audit where applicable,
- secret scanning,
- fuzz targets.

Pin security-sensitive GitHub Actions to immutable commit SHAs where practical.

## Hostile-Agent integration harness

Simulate:
- revoked/expired/wrong Agent credential,
- wrong tenant/Agent identity,
- malformed/oversized messages,
- replay,
- negative/huge counters,
- future time,
- XSS telemetry,
- cross-Agent device ownership,
- proxy SSRF,
- redirect abuse,
- reconnect storm,
- update tampering.

Security regression checks should be required on protected branches.

---

# P1-04 — Release provenance, SBOM and dependency hygiene

Every production release should produce/store:
- git commit SHA,
- toolchain version,
- artifact SHA-256,
- SBOM,
- signed update metadata,
- provenance/attestation where feasible.

Document vulnerability exception policy.

No release signing secret in GitHub Actions plaintext variables if a stronger signing mechanism is available.

---

# P1-05 — Security operations runbooks and external validation

Create operational runbooks for:

## Compromised customer PC
- quarantine Agent,
- revoke certificate,
- collect minimal evidence,
- re-enroll after host remediation.

## Server compromise
- revoke admin sessions,
- rotate application secrets,
- assess DB exposure,
- Agent identities remain independently revocable,
- release signing trust remains unaffected.

## Release-key compromise
- emergency root/key rotation procedure,
- block unsafe updates,
- fleet recovery process.

## Database leak
- demonstrate DB does not contain reusable Agent private credentials.

## Final pre-production test matrix

Must include:
- customer PC fully compromised,
- Agent credential theft attempt,
- DB dump leak,
- stored XSS,
- tenant escape,
- proxy SSRF/pivot,
- update-server compromise,
- old signed release,
- wrong-platform release,
- junction/reparse update attack,
- 100-Agent reconnect storm,
- one-Agent telemetry flood.

Before large-scale production rollout, perform an independent penetration test focused on Agent -> server -> admin/fleet pivot paths.

---

# Architecture invariants

These are non-negotiable unless this document is deliberately revised after security review.

1. A customer Agent is never a trusted network peer merely because it authenticated.
2. One Agent credential maps to one Agent/tenant only.
3. No Agent command protocol provides arbitrary code execution.
4. No printer proxy becomes a generic LAN proxy.
5. Printer-controlled HTML does not share the admin origin/session.
6. Application-server compromise alone cannot sign a new trusted Agent binary.
7. Database compromise alone does not reveal reusable fleet Agent credentials.
8. Release signing, Agent identity signing and application/session secrets are separate trust domains.
9. All untrusted input is length/type/range bounded before expensive processing or persistence.
10. Security-critical revocation/quarantine takes effect on active as well as new connections.

---

# Suggested Codex command sequence

Use one task at a time.

Example:

```text
Read .github/SECURITY_HARDENING_PLAN.md and implement P0-08 only.
Inspect the current code first, preserve existing behavior where possible,
add tests for every acceptance condition, and do not start any other task.
Return a summary of changed files, tests, migration impact and remaining risk.
```

Then:

```text
Implement P0-01 from .github/SECURITY_HARDENING_PLAN.md.
Before coding, map the current Agent enrollment/authentication flow.
Use a migration-compatible design and add integration tests for
wrong-Agent, wrong-tenant, expired, revoked and legacy migration cases.
```

Do not instruct Codex to “implement the whole security plan” in one PR.
