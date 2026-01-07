# 🚀 Quick Start Guide

## Prerequisites
- Ubuntu/Debian server with root access
- Discord webhook URL

## Step 1: Create Discord Webhook
1. Go to your Discord server
2. Server Settings → Integrations → Webhooks
3. New Webhook → Copy Webhook URL

## Step 2: Install

```bash
# Clone or download this repo to your server
cd /tmp
git clone <your-repo> server-monitor
cd server-monitor

# Set your Discord webhook
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR/WEBHOOK"

# Run installer
sudo -E ./install.sh
```

## Step 3: Verify

```bash
sudo ./verify.sh
```

You should see:
- All services running ✓
- Test alert in Discord ✓

## What Gets Installed

| Component | Purpose |
|-----------|---------|
| auditd | System call monitoring |
| AIDE | File integrity |
| fail2ban | Brute force protection |
| rkhunter | Rootkit detection |
| systemd services | Persistent monitoring |

## Monitoring Commands

```bash
# View real-time logs
journalctl -u server-process-monitor -f

# Check service status
systemctl status server-watchdog

# View local alerts log
tail -f /opt/server-monitor/logs/monitor.log

# Run manual AIDE check
aide --check

# Run rootkit scan
/opt/server-monitor/bin/rootkit-scan.sh
```

## Customization

### Whitelist Processes
Edit `/opt/server-monitor/etc/whitelist.conf`:
```
^/usr/bin/your-app$
^/opt/your-service/
```

### Adjust Rate Limiting
Edit `/opt/server-monitor/etc/config.env`:
```
RATE_LIMIT_SECONDS=120  # Increase to reduce alerts
```

## After Legitimate Changes

When you make intentional changes to system files:

```bash
# Update AIDE baseline
sudo aide --update
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Update rkhunter baseline
sudo rkhunter --propupd
```

## Uninstall

```bash
sudo ./uninstall.sh
```

## Troubleshooting

### No Discord alerts
```bash
# Test webhook directly
curl -H "Content-Type: application/json" \
  -d '{"content":"Test"}' \
  "YOUR_WEBHOOK_URL"
```

### Services not starting
```bash
journalctl -u server-process-monitor --no-pager -n 50
```

### Too many alerts
1. Add legitimate processes to whitelist
2. Increase RATE_LIMIT_SECONDS in config
