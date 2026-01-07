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
