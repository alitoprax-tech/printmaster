# Service Mode - Quick Reference

## Overview

PrintMaster Agent can run as a system service for production deployments. This ensures the agent starts automatically on boot and runs continuously in the background.

## Commands

```bash
# Install service (requires admin/root)
printmaster-agent --service install

# Start service
printmaster-agent --service start

# Stop service
printmaster-agent --service stop

# Uninstall service
printmaster-agent --service uninstall

# Run in foreground (testing)
printmaster-agent --service run

# Interactive mode (default)
printmaster-agent
```

## Platform-Specific Details

### Windows

**Requirements**: Administrator privileges

**Data Directory**: `C:\ProgramData\PrintMaster\`

**Installation**:
```powershell
# Open PowerShell as Administrator
cd C:\Path\To\PrintMaster
.\printmaster-agent.exe --service install
.\printmaster-agent.exe --service start

# Verify service is running
Get-Service PrintMasterAgent

# Check logs
Get-Content "C:\ProgramData\PrintMaster\agent\logs\agent.log" -Tail 50
```

**Access Web UI**: http://localhost:8080 (or https://localhost:8443)

### Linux

**Requirements**: Root privileges

**Data Directories**:
- Config: `/etc/printmaster/`
- Data: `/var/lib/printmaster/`
- Logs: `/var/log/printmaster/`

**Installation**:
```bash
# Install service
sudo ./printmaster-agent --service install

# OR manually with systemd unit file:
sudo cp agent/printmaster-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable printmaster-agent
sudo systemctl start printmaster-agent

# Check status
sudo systemctl status printmaster-agent

# View logs
sudo journalctl -u printmaster-agent -f
```

### macOS

**Requirements**: Root privileges

**Data Directory**: `/Library/Application Support/PrintMaster/`

**Installation**:
```bash
# Install service
sudo ./printmaster-agent --service install

# Start service
sudo launchctl load /Library/LaunchDaemons/com.printmaster.agent.plist

# Stop service
sudo launchctl unload /Library/LaunchDaemons/com.printmaster.agent.plist

# View logs
log show --predicate 'process == "printmaster-agent"' --last 1h
```

## Troubleshooting

### Service won't start

**Windows**:
```powershell
# Check Windows Event Viewer
eventvwr.msc
# Navigate to: Applications and Services Logs > PrintMasterAgent
```

**Linux**:
```bash
# Check service status
sudo systemctl status printmaster-agent

# View recent logs
sudo journalctl -u printmaster-agent -n 100 --no-pager

# Check for permission issues
sudo ls -la /var/lib/printmaster /var/log/printmaster
```

### Cannot access web UI

1. Check if service is running
2. Verify firewall allows port 8080/8443
3. Check settings in agent config database
4. Review logs for port binding errors

### Service fails to install

- **Windows**: Run PowerShell as Administrator
- **Linux/macOS**: Use `sudo` for installation
- Verify binary has execute permissions (`chmod +x printmaster-agent`)

## Configuration

Service uses the same configuration as interactive mode:
- Settings stored in agent database (`agent.db`)
- Web UI accessible at configured ports
- All discovery and proxy features available

## Security

When running as service:
- **Windows**: Runs as the virtual service account `NT SERVICE\PrintMasterAgent`.
  Installation enables the service SID and applies a protected ACL to
  `C:\ProgramData\PrintMaster` so only the service, SYSTEM, and local
  Administrators can access state. The account has no interactive logon.
- **Linux**: Runs as dedicated `printmaster` user (create with `useradd -r printmaster`)
- **macOS**: Runs as root (can be configured to run as specific user)

For production deployments:
1. Use dedicated service account with minimal privileges
2. Configure firewall rules appropriately
3. Enable HTTPS for web UI access
4. Review security settings in Web UI > Settings > Security

### Windows identity key protection

On Windows, new enrollment, pending, renewal, and migration keys first use the
Microsoft Platform Crypto Provider when an available TPM can create an ECDSA
P-256 non-exportable key. If hardware CNG is unavailable, the Microsoft
Software Key Storage Provider is attempted with the same non-exportable policy
and service ACL. The identity generation stores only the CNG provider/key
reference and certificate; no raw private-key PEM is written to disk. If CNG
is unavailable, the Agent uses user-scoped DPAPI only after verifying that the
current process token is the installed `NT SERVICE\PrintMasterAgent` identity.
Encryption and decryption must therefore both run under that service account;
an interactive or administrator process fails closed and does not write a
plaintext or machine-scoped fallback key. A legacy plaintext generation is
copied to protected storage, reopened and verified before the old generation
is removed; if migration cannot be completed, the old identity is retained
and the service refuses to continue with an unprotected replacement.

The updater remains in the existing Agent process for now. Separating update
installation into a narrowly privileged helper is deferred to P0-07; this
change does not add a generic process, shell, PowerShell, registry, or
arbitrary file-write capability.

## See Also

- [Full Service Deployment Guide](../docs/SERVICE_DEPLOYMENT.md)
- [Configuration Guide](../docs/CONFIGURATION.md)
- [Security Architecture](../docs/SECURITY_ARCHITECTURE.md)
