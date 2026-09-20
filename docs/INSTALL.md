# Installation Guide

This guide covers installing PrintMaster on all supported platforms.

> For an Internet-facing deployment, read the [production deployment
> checklist](PRODUCTION-DEPLOYMENT-TR.md) first. Use a reviewed/pinned image or
> a binary built from the hardened branch, HTTPS at the reverse proxy, strong
> secrets, and private database ports. The examples below keep the server port
> on loopback.

## Table of Contents

- [Quick Install](#quick-install)
- [Server Installation](#server-installation)
  - [Docker (Recommended)](#docker-recommended)
  - [Unraid](#unraid)
  - [Manual Installation](#manual-server-installation)
- [Agent Installation](#agent-installation)
  - [Windows](#windows)
  - [Linux (Debian/Ubuntu)](#linux-debianubuntu)
  - [Linux (Fedora/RHEL)](#linux-fedorarhel)
  - [macOS](#macos)
  - [Docker](#docker-agent)
- [First-Time Setup](#first-time-setup)

---

## Quick Install

### Server (Docker)

```bash
# server.env must contain strong ADMIN_PASSWORD and, when needed, a random
# INIT_SECRET generated with: openssl rand -hex 32
docker run -d \
  --name printmaster-server \
  -p 127.0.0.1:9090:9090 \
  -v printmaster-data:/var/lib/printmaster/server \
  -e BIND_ADDRESS=0.0.0.0 \
  -e BEHIND_PROXY=true \
  --env-file server.env \
  ghcr.io/mstrhakr/printmaster-server:<reviewed-version>
```

Put the container behind an HTTPS reverse proxy and set
`SERVER_EXTERNAL_URL=https://printmaster.example.com` plus a narrow
`TRUSTED_PROXIES` value. For a local smoke test only, use
`http://127.0.0.1:9090`; do not publish this port to the Internet.

### Agent (Windows)

Download and run the MSI installer from [GitHub Releases](https://github.com/mstrhakr/printmaster/releases).

### Agent (Linux)

```bash
# Debian/Ubuntu
curl -fsSL https://mstrhakr.github.io/printmaster/install.sh | sudo bash

# Or manual apt install
curl -fsSL https://mstrhakr.github.io/printmaster/gpg.key | \
  sudo gpg --dearmor -o /usr/share/keyrings/printmaster.gpg
echo "deb [signed-by=/usr/share/keyrings/printmaster.gpg] https://mstrhakr.github.io/printmaster stable main" | \
  sudo tee /etc/apt/sources.list.d/printmaster.list
sudo apt-get update && sudo apt-get install -y printmaster-agent
```

---

## Server Installation

The server provides centralized management for multiple agents. If you only need to monitor printers at a single site, you can run the agent standalone without a server.

### Docker (Recommended)

Docker is the recommended deployment method for the server.

#### Prerequisites
- Docker Engine 20.10 or later
- Docker Compose (optional but recommended)

#### Using Docker Run

```bash
# Basic setup; pin the image to a reviewed version and keep server.env private.
docker run -d \
  --name printmaster-server \
  -p 127.0.0.1:9090:9090 \
  -v printmaster-data:/var/lib/printmaster/server \
  -v printmaster-logs:/var/log/printmaster/server \
  -e BIND_ADDRESS=0.0.0.0 \
  -e BEHIND_PROXY=true \
  --env-file server.env \
  ghcr.io/mstrhakr/printmaster-server:<reviewed-version>
```

#### Using Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'
services:
  printmaster-server:
    image: ghcr.io/mstrhakr/printmaster-server:<reviewed-version>
    container_name: printmaster-server
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - printmaster-data:/var/lib/printmaster/server
      - printmaster-logs:/var/log/printmaster/server
    environment:
      - BIND_ADDRESS=0.0.0.0
      - BEHIND_PROXY=true
      - SERVER_EXTERNAL_URL=https://printmaster.example.com
      - TRUSTED_PROXIES=127.0.0.1/32
      - LOG_LEVEL=info
      # Set INIT_SECRET only when automatic enrollment is required; use a
      # random value with 32-4096 bytes. Prefer one-time join tokens.
      - INIT_SECRET=${INIT_SECRET:?Set a random INIT_SECRET in the environment}
    restart: unless-stopped

volumes:
  printmaster-data:
  printmaster-logs:
```

Start with:
```bash
docker compose up -d
```

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_PASSWORD` | required | Admin password (minimum 16 characters; no default) |
| `INIT_SECRET` | optional | Auto-enrollment bearer secret; 32-4096 bytes, no whitespace |
| `LOG_LEVEL` | `info` | Logging level: debug, info, warn, error |
| `BEHIND_PROXY` | `false` | Set to `true` only when an HTTPS reverse proxy fronts the server |
| `BIND_ADDRESS` | `127.0.0.1` | Keep loopback; use `0.0.0.0` only for a private container network |
| `SERVER_HTTP_PORT` | `9090` | HTTP backend/redirect port |
| `SERVER_HTTPS_PORT` | `9443` | HTTPS port |

> **Important**: Set `ADMIN_PASSWORD` before the first run. The password can only be set during initial database creation.

#### Behind a Reverse Proxy

If using Nginx Proxy Manager, Traefik, or another reverse proxy:

```yaml
environment:
  - BEHIND_PROXY=true
  - BIND_ADDRESS=0.0.0.0
```

Configure your proxy to:
- Forward to port 9090
- Enable WebSocket support (required for real-time features)
- Handle SSL termination

### Unraid

1. **Using Community Applications** (Easiest):
   - Install the Community Applications plugin
   - Search for "PrintMaster Server"
   - Click Install and configure

2. **Manual Docker Setup**:
   - Go to Docker tab → Add Container
   - Repository: `ghcr.io/mstrhakr/printmaster-server:<reviewed-version>`
   - Port: 9090 → 9090
   - Path: `/mnt/user/appdata/printmaster-server/data` → `/var/lib/printmaster/server`
   - Path: `/mnt/user/appdata/printmaster-server/logs` → `/var/log/printmaster/server`

See [Unraid Deployment Guide](dev/UNRAID_DEPLOYMENT.md) for detailed instructions.

### Manual Server Installation

Download the server binary from [GitHub Releases](https://github.com/mstrhakr/printmaster/releases) and run:

```bash
# Linux/macOS
./printmaster-server

# Windows
.\printmaster-server.exe
```

---

## Agent Installation

### Windows

#### MSI Installer (Recommended)

1. Download the exact reviewed MSI from [GitHub Releases](https://github.com/mstrhakr/printmaster/releases) and verify its published checksum/signature
2. Run the installer
3. The agent will be installed as a Windows service and start automatically
4. Access the web UI at `http://localhost:8080`

#### Manual Installation

```powershell
# Download the exact reviewed asset from the selected release tag. Do not use
# the mutable /releases/latest/download URL for a production installation.
Invoke-WebRequest -Uri "https://github.com/mstrhakr/printmaster/releases/download/<reviewed-tag>/printmaster-agent-windows-amd64.exe" -OutFile "printmaster-agent.exe"

# Install as service (requires Administrator)
.\printmaster-agent.exe --service install

# Start the service
.\printmaster-agent.exe --service start
```

#### Service Management

```powershell
# Check status
Get-Service PrintMasterAgent

# Stop service
.\printmaster-agent.exe --service stop

# Uninstall service
.\printmaster-agent.exe --service uninstall
```

### Linux (Debian/Ubuntu)

#### APT Repository (Recommended)

```bash
# Add repository
curl -fsSL https://mstrhakr.github.io/printmaster/gpg.key | \
  sudo gpg --dearmor -o /usr/share/keyrings/printmaster.gpg
echo "deb [signed-by=/usr/share/keyrings/printmaster.gpg] https://mstrhakr.github.io/printmaster stable main" | \
  sudo tee /etc/apt/sources.list.d/printmaster.list

# Install
sudo apt-get update
sudo apt-get install -y printmaster-agent

# The service starts automatically
systemctl status printmaster-agent
```

#### With GPG Signature Verification (Recommended for Production)

```bash
# Import GPG key
curl -fsSL https://mstrhakr.github.io/printmaster/gpg.key | \
  sudo gpg --dearmor -o /usr/share/keyrings/printmaster.gpg

# Add repository with signature verification
echo "deb [signed-by=/usr/share/keyrings/printmaster.gpg] https://mstrhakr.github.io/printmaster stable main" | \
  sudo tee /etc/apt/sources.list.d/printmaster.list

# Install
sudo apt-get update
sudo apt-get install -y printmaster-agent
```

#### Manual Installation

```bash
# Download the exact reviewed asset and verify its checksum from the release
# page before installing. Replace <reviewed-tag> with the chosen release tag.
wget https://github.com/mstrhakr/printmaster/releases/download/<reviewed-tag>/printmaster-agent-linux-amd64

# Make executable
chmod +x printmaster-agent-linux-amd64
sudo mv printmaster-agent-linux-amd64 /usr/local/bin/printmaster-agent

# Install as service
sudo printmaster-agent --service install
sudo systemctl start PrintMasterAgent
```

### Linux (Fedora/RHEL)

#### DNF Repository (Recommended)

```bash
# Import GPG key (recommended)
sudo rpm --import https://mstrhakr.github.io/printmaster/gpg.key

# Add repository
sudo dnf config-manager addrepo --from-repofile=https://mstrhakr.github.io/printmaster/printmaster.repo

# Install
sudo dnf install -y printmaster-agent

# The service starts automatically
systemctl status printmaster-agent
```

#### Important Linux Paths

| Path | Description |
|------|-------------|
| `/usr/bin/printmaster-agent` | Agent binary |
| `/etc/printmaster/agent.toml` | Configuration file |
| `/var/lib/printmaster` | Data directory (SQLite DB) |
| `/var/log/printmaster` | Log files |

### macOS

```bash
# Download the exact reviewed asset and verify its checksum from the release
# page before installing. Replace <reviewed-tag> with the chosen release tag.
curl -LO https://github.com/mstrhakr/printmaster/releases/download/<reviewed-tag>/printmaster-agent-darwin-amd64

# Make executable
chmod +x printmaster-agent-darwin-amd64
sudo mv printmaster-agent-darwin-amd64 /usr/local/bin/printmaster-agent

# Install as service
sudo printmaster-agent --service install

# Start service
sudo launchctl load /Library/LaunchDaemons/com.printmaster.agent.plist
```

### Docker Agent

The agent can also run in Docker for specialized deployments:

```bash
docker run -d \
  --name printmaster-agent \
  --network host \
  -v printmaster-agent-data:/var/lib/printmaster/agent \
  ghcr.io/mstrhakr/printmaster-agent:<reviewed-version>
```

> **Note**: `--network host` is required for SNMP discovery to work properly.

---

## First-Time Setup

### Accessing the Web UI

| Component | Default URL | Default Port |
|-----------|-------------|--------------|
| Agent | `http://localhost:8080` | 8080 |
| Server | `http://localhost:9090` | 9090 |

### Server First Login

1. Open the canonical HTTPS address configured for your deployment
2. Log in with:
   - Username: `admin`
   - Password: The password you set via `ADMIN_PASSWORD`

### Connecting an Agent to the Server

1. Open the agent's web UI at `http://agent-ip:8080`
2. Go to **Settings** → **Server Connection**
3. Enter your server URL: `https://your-server.example.com`
4. Click **Save**

Or edit the agent's config file:

```toml
[server]
enabled = true
url = "https://your-server.example.com"
```

### Next Steps

- [Getting Started Guide](GETTING_STARTED.md) - Configure discovery and scan your first printers
- [Features Guide](FEATURES.md) - Learn about all available features
- [Configuration Guide](CONFIGURATION.md) - Fine-tune your setup

---

## Upgrading

### Docker

```bash
docker pull ghcr.io/mstrhakr/printmaster-server:<reviewed-version>
docker compose down
docker compose up -d
```

### Linux (APT)

```bash
sudo apt-get update
sudo apt-get upgrade printmaster-agent
```

### Linux (DNF)

```bash
sudo dnf upgrade printmaster-agent
```

### Windows

Run the new MSI installer - it will upgrade the existing installation.

### Auto-Updates

Agents support automatic updates. See [Configuration Guide](CONFIGURATION.md#auto-updates) for setup instructions.
