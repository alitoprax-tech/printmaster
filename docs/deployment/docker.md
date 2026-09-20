# Docker Deployment

Deploy PrintMaster Server using Docker containers with multi-architecture support.

> **Production security:** Pin the image to a reviewed release or digest, keep
> the published port on loopback, and place an HTTPS reverse proxy in front of
> it. Never copy a password into a command line. See
> [the production checklist](../PRODUCTION-DEPLOYMENT-TR.md).

## Quick Start

```bash
# server.env must contain ADMIN_PASSWORD (>=16 characters) and, only when
# automatic enrollment is needed, a random INIT_SECRET (32-4096 bytes).
docker run -d \
  --name printmaster-server \
  -p 127.0.0.1:9090:9090 \
  -v printmaster-data:/var/lib/printmaster/server \
  -e BIND_ADDRESS=0.0.0.0 \
  -e BEHIND_PROXY=true \
  --env-file server.env \
  ghcr.io/mstrhakr/printmaster-server:<reviewed-version>
```

Use `http://127.0.0.1:9090` only for a local smoke test. Public access must
come through the reverse proxy at the configured HTTPS `SERVER_EXTERNAL_URL`.

---

## Supported Architectures

All images are built for multiple architectures automatically:

| Architecture | Platform | Use Case |
|--------------|----------|----------|
| `linux/amd64` | x86_64 servers | Intel/AMD servers, cloud VMs |
| `linux/arm64` | ARM 64-bit | Apple Silicon, AWS Graviton, Raspberry Pi 4+ |
| `linux/arm/v7` | ARM 32-bit | Raspberry Pi 3/4 (32-bit OS) |

Docker automatically pulls the correct architecture for your platform.

## Image Details

**Base Image**: `gcr.io/distroless/static:nonroot`
- **Size**: ~30MB (70% smaller than Alpine-based)
- **Security**: No shell, no package manager, minimal attack surface
- **User**: Runs as non-root (UID 65532)

**Image tags:**
- `<reviewed-version>` - Pin the exact release selected for production
- `latest` - Moving convenience tag for evaluation only; do not use it for customer data

---

## Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'
services:
  printmaster-server:
    image: ghcr.io/mstrhakr/printmaster-server:<reviewed-version>
    container_name: printmaster-server
    ports:
      - "127.0.0.1:9090:9090"
      - "127.0.0.1:9443:9443"  # HTTPS (publish through a reverse proxy)
    volumes:
      - printmaster-data:/var/lib/printmaster/server
      - printmaster-logs:/var/log/printmaster/server
    environment:
      - BIND_ADDRESS=0.0.0.0
      - BEHIND_PROXY=true
      - SERVER_EXTERNAL_URL=https://printmaster.example.com
      - TRUSTED_PROXIES=127.0.0.1/32
      - LOG_LEVEL=info
      - PM_DISABLE_SELFUPDATE=true
      # Prefer one-time join tokens. Set INIT_SECRET only for controlled
      # bootstrap automation; it must be a private random value of at least
      # 32 bytes.
      - INIT_SECRET=${INIT_SECRET:-}
    restart: unless-stopped

volumes:
  printmaster-data:
  printmaster-logs:
```

Start with:
```bash
docker compose up -d
```

---

## Environment Variables

### Essential

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_PASSWORD` | required | **Set before first run; no default is accepted.** |
| `BIND_ADDRESS` | `127.0.0.1` | Keep loopback; use `0.0.0.0` only inside a private container network |
| `INIT_SECRET` | optional | Auto-enrollment bearer secret; 32-4096 bytes, no whitespace |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

### Network & Ports

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_HTTP_PORT` | `9090` | HTTP port |
| `SERVER_HTTPS_PORT` | `9443` | HTTPS port |
| `BEHIND_PROXY` | `false` | Set `true` if behind reverse proxy |
| `PROXY_USE_HTTPS` | `false` | Proxy terminates SSL |

### TLS/HTTPS

| Variable | Default | Description |
|----------|---------|-------------|
| `TLS_MODE` | `self-signed` | `self-signed`, `custom`, `letsencrypt` |
| `TLS_CERT_PATH` | — | Certificate path (manual mode) |
| `TLS_KEY_PATH` | — | Key path (manual mode) |

### Let's Encrypt

| Variable | Description |
|----------|-------------|
| `LETSENCRYPT_DOMAIN` | Domain for certificate |
| `LETSENCRYPT_EMAIL` | Notification email |
| `LETSENCRYPT_ACCEPT_TOS` | Accept ToS (`true`) |

### Agent Management

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTO_APPROVE_AGENTS` | `false` | Auto-approve new agents |
| `AGENT_TIMEOUT_MINUTES` | `5` | Timeout before marking offline |

### Container Detection

| Variable | Effect |
|----------|--------|
| `PM_DISABLE_SELFUPDATE` | Disable self-update (recommended for Docker) |
| `CONTAINER=docker` | Auto-detected, disables self-update |

See [Environment Variables Reference](../api/environment-variables.md) for the complete list.

---

## Behind a Reverse Proxy

### Nginx Proxy Manager / Traefik / Caddy

```yaml
environment:
  - BEHIND_PROXY=true
  - BIND_ADDRESS=0.0.0.0
  - PROXY_USE_HTTPS=true  # If proxy handles SSL
```

**Reverse proxy requirements:**
- Forward to port `9090`
- Enable **WebSocket support** (required for real-time features)
- Handle SSL termination

### Nginx Configuration Example

```nginx
server {
    listen 443 ssl;
    server_name printmaster.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://printmaster-server:9090;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Volumes & Data

### Recommended Volume Mounts

| Container Path | Purpose |
|----------------|---------|
| `/var/lib/printmaster/server` | Database and config |
| `/var/log/printmaster/server` | Log files |

The TimescaleDB PostgreSQL 18 Compose image mounts its database volume at
`/var/lib/postgresql`. Do not change this to `/var/lib/postgresql/data`; that
older mount layout can prevent the PG18 image from finding its data directory.

For PostgreSQL major-version migrations and TimescaleDB restore hooks, see
[PostgreSQL and TimescaleDB Upgrades](database-upgrade.md).

### Backup

```bash
# Stop container first for consistent backup
docker stop printmaster-server

# Backup database
docker cp printmaster-server:/var/lib/printmaster/server/server.db ./backup-$(date +%Y%m%d).db

# Restart
docker start printmaster-server
```

---

## Health Check

The distroless image doesn't include curl/wget. Use external monitoring:

```bash
# From host
curl -s http://localhost:9090/api/v1/health

# Docker health check (compose v3.8+)
healthcheck:
  test: ["CMD-SHELL", "wget -q -O /dev/null http://localhost:9090/api/v1/health || exit 1"]
  interval: 30s
  timeout: 10s
  retries: 3
```

---

## Updating

```bash
# Pull latest image
docker pull ghcr.io/mstrhakr/printmaster-server:<reviewed-version>

# Recreate container
docker compose down
docker compose up -d

# Check version
docker logs printmaster-server | head -5
```

## PostgreSQL and TimescaleDB upgrades

The repository Compose examples use `timescale/timescaledb:latest-pg18` for
new deployments. Changing a PostgreSQL major version while reusing an existing
database volume is not a valid upgrade and can make the database refuse to
start. Never delete the old volume as a workaround.

For the required backup, new-volume migration, and verification steps, see
[PostgreSQL and TimescaleDB Upgrades](database-upgrade.md).

---

## Agent in Docker

For specialized deployments (not typical):

```bash
docker run -d \
  --name printmaster-agent \
  --network host \
  -v printmaster-agent-data:/var/lib/printmaster/agent \
  -e SERVER_ENABLED=true \
  -e SERVER_URL=https://printmaster.example.com \
  ghcr.io/mstrhakr/printmaster-agent:<reviewed-version>
```

> **Note**: `--network host` is required for SNMP discovery to work properly.

---

## See Also

- [Unraid Deployment](unraid.md)
- [Installation Guide](../INSTALL.md)
- [Configuration Guide](../CONFIGURATION.md)
