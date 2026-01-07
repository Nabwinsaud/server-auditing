# 🔒 Server Intrusion Detection & Alert System

## ⚡ One-Line Install

```bash
curl -sSL https://raw.githubusercontent.com/Nabwinsaud/server-auditing/main/setup.sh | sudo DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR/WEBHOOK" bash
```

That's it! Check your Discord for a confirmation alert.

---

## Threat Model

### What Attackers Typically Do
1. **Persistence**: Install backdoors via cron, systemd, rc.local, SSH keys
2. **Evasion**: Delete logs, modify timestamps, use nohup/screen/tmux
3. **Privilege Escalation**: Exploit SUID binaries, kernel vulnerabilities
4. **Lateral Movement**: Scan internal networks, steal credentials
5. **Defense Evasion**: Kill monitoring processes, modify audit rules

### How This Design Defeats Each Tactic

| Attack Tactic | Defense Mechanism |
|---------------|-------------------|
| Cron tampering | Systemd services + watchdog + auditd alerts |
| Log deletion | Auditd immutable mode + real-time Discord alerts |
| Process hiding | Multiple independent process monitors |
| Rootkit installation | rkhunter + AIDE file integrity |
| Monitoring kill | Watchdog auto-restart + tamper detection |
| Audit rule changes | Audit rules monitor themselves |

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         DETECTION LAYER                                  │
├──────────────┬──────────────┬──────────────┬──────────────┬─────────────┤
│   AIDE       │   auditd     │  fail2ban    │  rkhunter    │  netwatch   │
│  (files)     │  (syscalls)  │  (brute)     │  (rootkits)  │  (network)  │
└──────┬───────┴──────┬───────┴──────┬───────┴──────┬───────┴──────┬──────┘
       │              │              │              │              │
       └──────────────┴──────────────┼──────────────┴──────────────┘
                                     │
                           ┌─────────▼─────────┐
                           │   ALERT ROUTER    │
                           │  (rate-limited)   │
                           └─────────┬─────────┘
                                     │
                           ┌─────────▼─────────┐
                           │  DISCORD WEBHOOK  │
                           └───────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                      SELF-PROTECTION LAYER                              │
├─────────────────────┬─────────────────────┬─────────────────────────────┤
│  Watchdog Service   │  Immutable Files    │  Audit Self-Monitoring      │
│  (auto-restart)     │  (chattr +i)        │  (detect rule changes)      │
└─────────────────────┴─────────────────────┴─────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                      EXECUTION MECHANISMS                               │
├─────────────────────┬─────────────────────┬─────────────────────────────┤
│  systemd services   │  systemd timers     │  inotifywait (realtime)     │
│  (primary)          │  (backup)           │  (file events)              │
└─────────────────────┴─────────────────────┴─────────────────────────────┘
```

---

## Quick Start

### Option 1: One-Line Install (Recommended)
```bash
curl -sSL https://raw.githubusercontent.com/Nabwinsaud/server-auditing/main/setup.sh | sudo DISCORD_WEBHOOK="YOUR_WEBHOOK_URL" bash
```

### Option 2: Clone and Install
```bash
git clone https://github.com/Nabwinsaud/server-auditing.git
cd server-auditing
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR_WEBHOOK"
sudo -E ./install.sh
sudo ./verify.sh
```

### Uninstall
```bash
curl -sSL https://raw.githubusercontent.com/Nabwinsaud/server-auditing/main/uninstall.sh | sudo bash
```

---

## Directory Structure

```
/opt/server-monitor/
├── bin/
│   ├── alert.sh              # Discord alert sender
│   ├── file-monitor.sh       # AIDE wrapper
│   ├── process-monitor.sh    # Process watcher
│   ├── network-monitor.sh    # Connection monitor
│   ├── ssh-monitor.sh        # SSH login monitor
│   └── watchdog.sh           # Self-protection
├── etc/
│   ├── config.env            # Configuration
│   └── whitelist.conf        # Known-good processes
├── var/
│   ├── state/                # State files
│   └── cache/                # Rate limiting cache
└── logs/
    └── monitor.log           # Local backup log
```

---

## Components

1. **Detection Scripts** - Monitor files, processes, network, SSH
2. **Alert System** - Rate-limited Discord notifications
3. **Systemd Services** - Persistent, auto-restarting monitors
4. **Watchdog** - Monitors the monitors
5. **Tamper Protection** - Immutable files, audit rules

---

## Files in This Repository

- `install.sh` - One-command installer
- `scripts/` - All monitoring scripts
- `systemd/` - Service unit files
- `audit/` - Audit rules
- `verify.sh` - Verification commands

---

## 📖 How to Use

### Check Service Status
```bash
# See all monitoring services
sudo systemctl status server-*

# Check specific service
sudo systemctl status server-ssh-monitor
sudo systemctl status server-process-monitor
```

### View Logs
```bash
# Real-time logs from SSH monitor
sudo journalctl -u server-ssh-monitor -f

# All monitor logs
sudo journalctl -u server-process-monitor -u server-ssh-monitor -u server-network-monitor -f

# Local log file
sudo tail -f /opt/server-monitor/logs/monitor.log
```

### Send Test Alert
```bash
sudo /opt/server-monitor/bin/alert.sh test "🧪 Test Alert" "This is a test message" medium
```

### Manage Services
```bash
# Restart a service
sudo systemctl restart server-ssh-monitor

# Stop all monitoring temporarily
sudo systemctl stop server-process-monitor server-ssh-monitor server-network-monitor

# Start all monitoring
sudo systemctl start server-process-monitor server-ssh-monitor server-network-monitor
```

### Update Configuration
```bash
# Edit config (need to remove immutable flag first)
sudo chattr -i /opt/server-monitor/etc/config.env
sudo nano /opt/server-monitor/etc/config.env
sudo chattr +i /opt/server-monitor/etc/config.env

# Restart services to apply
sudo systemctl restart server-ssh-monitor server-process-monitor
```

### Add/Update Single Config Value
```bash
# Remove protection
sudo chattr -i /opt/server-monitor/etc/config.env

# Add timezone
echo 'TIMEZONE="Asia/Kathmandu"' | sudo tee -a /opt/server-monitor/etc/config.env

# Or change rate limit
sudo sed -i 's/RATE_LIMIT_SECONDS=300/RATE_LIMIT_SECONDS=600/' /opt/server-monitor/etc/config.env

# Restore protection
sudo chattr +i /opt/server-monitor/etc/config.env
```

### View Current Config
```bash
sudo cat /opt/server-monitor/etc/config.env
```

---

## 🗑️ How to Uninstall

### Option 1: One-Line Uninstall
```bash
curl -sSL https://raw.githubusercontent.com/Nabwinsaud/server-auditing/main/uninstall.sh | sudo bash
```

### Option 2: Manual Uninstall
```bash
# Stop all services
sudo systemctl stop server-process-monitor server-network-monitor server-ssh-monitor server-watchdog server-file-monitor.timer server-rootkit-scan.timer

# Remove immutable flag from protected files
sudo chattr -i /opt/server-monitor/bin/*.sh
sudo chattr -i /opt/server-monitor/etc/config.env
sudo chattr -i /etc/systemd/system/server-*.service
sudo chattr -i /etc/systemd/system/server-*.timer

# Disable services
sudo systemctl disable server-process-monitor server-network-monitor server-ssh-monitor server-watchdog server-file-monitor.timer server-rootkit-scan.timer

# Remove files
sudo rm -rf /opt/server-monitor
sudo rm -f /etc/systemd/system/server-*.service
sudo rm -f /etc/systemd/system/server-*.timer
sudo rm -f /etc/audit/rules.d/server-monitor.rules

# Reload systemd
sudo systemctl daemon-reload
sudo systemctl restart auditd
```

---

## 🔔 Alert Types

| Alert | Severity | Trigger |
|-------|----------|---------|
| User Login | 🟢 LOW | Normal SSH login |
| Root Login | 🟠 HIGH | Root SSH login |
| Failed Login Attempts | 🟠 HIGH | >5 failed SSH attempts |
| Brute Force Attack | 🔴 CRITICAL | >20 failed attempts |
| Invalid Username | 🟡 MEDIUM | >3 invalid user attempts |
| Sensitive Command | 🟠 HIGH | sudo passwd/shadow/etc |
| Root Access | 🟠 HIGH | su to root |
| Service Down | 🔴 CRITICAL | nginx/mysql/docker/etc stopped |
| Service Recovered | 🟢 LOW | Service came back online |
| Monitor Down | 🔴 CRITICAL | Monitoring service stopped |
| File Change | 🟠 HIGH | System file modified |
| Disk Critical | 🟠 HIGH | Disk usage >90% |

### 🤖 Auto-Detected Services

The watchdog **automatically detects** and monitors these services if installed:

| Category | Services |
|----------|----------|
| Web Servers | nginx, apache2, httpd, caddy |
| Databases | mysql, mariadb, postgresql, mongod |
| Cache | redis, redis-server |
| Containers | docker |
| Security | auditd, fail2ban |
| SSH | sshd |

**No configuration needed!** If nginx is installed and enabled, it will be monitored automatically.

---

## ⚙️ Configuration Options

Edit `/opt/server-monitor/etc/config.env`:

| Option | Default | Description |
|--------|---------|-------------|
| `DISCORD_WEBHOOK` | - | Your Discord webhook URL |
| `HOSTNAME` | auto | Server name shown in alerts |
| `TIMEZONE` | UTC | Your local timezone for timestamps |
| `RATE_LIMIT_SECONDS` | 300 | Min seconds between same alert type |

### Timezone Examples
```bash
TIMEZONE="Asia/Kathmandu"    # Nepal
TIMEZONE="Asia/Kolkata"      # India
TIMEZONE="America/New_York"  # US East
TIMEZONE="Europe/London"     # UK
TIMEZONE="Asia/Tokyo"        # Japan
```

### Set Timezone During Install
```bash
curl -sSL https://raw.githubusercontent.com/Nabwinsaud/server-auditing/main/setup.sh | \
  sudo DISCORD_WEBHOOK="YOUR_WEBHOOK" TIMEZONE="Asia/Kathmandu" bash
```

---

## 🔒 Security Notes

- **Webhook URL**: Keep it secret! Anyone with it can send fake alerts
- **Config file**: Protected with `chmod 600` - only root can read
- **Scripts**: Protected with `chattr +i` - can't be modified without removing flag
- **No incoming ports**: Only makes outbound HTTPS requests to Discord
