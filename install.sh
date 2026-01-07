#!/bin/bash
#===============================================================================
# SERVER INTRUSION DETECTION SYSTEM - INSTALLER
# Run as root: sudo ./install.sh
#===============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

#-------------------------------------------------------------------------------
# Pre-flight checks
#-------------------------------------------------------------------------------
[[ $EUID -ne 0 ]] && error "Must run as root"
[[ -z "${DISCORD_WEBHOOK:-}" ]] && error "Set DISCORD_WEBHOOK environment variable first"

INSTALL_DIR="/opt/server-monitor"
HOSTNAME=$(hostname)

log "Starting installation on ${HOSTNAME}..."

#-------------------------------------------------------------------------------
# Install dependencies (non-interactive mode for curl | bash compatibility)
#-------------------------------------------------------------------------------
log "Installing required packages..."

# Set non-interactive mode to prevent dialogs blocking when running via curl | bash
export DEBIAN_FRONTEND=noninteractive

# Pre-configure packages that normally require interactive input
log "Pre-configuring packages..."

# Pre-configure postfix (required by some packages as dependency)
echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections 2>/dev/null || true
echo "postfix postfix/mailname string $(hostname -f 2>/dev/null || hostname)" | debconf-set-selections 2>/dev/null || true

# Pre-configure aide
echo "aide aide/initial_db boolean false" | debconf-set-selections 2>/dev/null || true

apt-get update -qq
apt-get install -y -qq \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    auditd \
    audispd-plugins \
    aide \
    fail2ban \
    rkhunter \
    chkrootkit \
    inotify-tools \
    jq \
    curl \
    ufw \
    > /dev/null 2>&1 || warn "Some packages may have failed to install"

#-------------------------------------------------------------------------------
# Create directory structure
#-------------------------------------------------------------------------------
log "Creating directory structure..."
mkdir -p "${INSTALL_DIR}"/{bin,etc,var/state,var/cache,logs}

#-------------------------------------------------------------------------------
# Create configuration
#-------------------------------------------------------------------------------
log "Creating configuration..."
cat > "${INSTALL_DIR}/etc/config.env" << EOF
# Server Monitor Configuration
# SECURITY: Keep this file protected (chmod 600)
DISCORD_WEBHOOK="${DISCORD_WEBHOOK}"
HOSTNAME="${HOSTNAME}"
INSTALL_DIR="${INSTALL_DIR}"
RATE_LIMIT_SECONDS=300
LOG_FILE="${INSTALL_DIR}/logs/monitor.log"
EOF
chmod 600 "${INSTALL_DIR}/etc/config.env"

# Create dedup directory for duplicate prevention
mkdir -p "${INSTALL_DIR}/var/dedup"

#-------------------------------------------------------------------------------
# Create whitelist (customize as needed)
#-------------------------------------------------------------------------------
cat > "${INSTALL_DIR}/etc/whitelist.conf" << 'EOF'
# Known-good processes (one regex per line)
^/usr/lib/systemd/
^/lib/systemd/
^/usr/sbin/cron$
^/usr/sbin/sshd$
^/usr/bin/bash$
^/usr/bin/dash$
EOF

#-------------------------------------------------------------------------------
# Copy scripts
#-------------------------------------------------------------------------------
log "Installing monitoring scripts..."

# Alert sender
cat > "${INSTALL_DIR}/bin/alert.sh" << 'SCRIPT'
#!/bin/bash
# Discord Alert Sender with Rate Limiting
source /opt/server-monitor/etc/config.env

CACHE_DIR="${INSTALL_DIR}/var/cache"
ALERT_TYPE="${1:-info}"
ALERT_TITLE="${2:-Alert}"
ALERT_MESSAGE="${3:-No message}"
SEVERITY="${4:-medium}"

# Rate limiting
CACHE_FILE="${CACHE_DIR}/alert_$(echo "${ALERT_TITLE}" | md5sum | cut -d' ' -f1)"
NOW=$(date +%s)

if [[ -f "$CACHE_FILE" ]]; then
    LAST_ALERT=$(cat "$CACHE_FILE")
    if (( NOW - LAST_ALERT < RATE_LIMIT_SECONDS )); then
        exit 0  # Rate limited
    fi
fi
echo "$NOW" > "$CACHE_FILE"

# Color based on severity
case "$SEVERITY" in
    critical) COLOR=15158332 ;;  # Red
    high)     COLOR=15105570 ;;  # Orange
    medium)   COLOR=16776960 ;;  # Yellow
    low)      COLOR=3066993 ;;   # Green
    *)        COLOR=3447003 ;;   # Blue
esac

# Build payload
PAYLOAD=$(jq -n \
    --arg title "🚨 ${ALERT_TITLE}" \
    --arg desc "$ALERT_MESSAGE" \
    --arg host "$HOSTNAME" \
    --arg time "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" \
    --arg user "${USER:-system}" \
    --arg sev "$SEVERITY" \
    --argjson color "$COLOR" \
    '{
        embeds: [{
            title: $title,
            description: $desc,
            color: $color,
            fields: [
                {name: "Host", value: $host, inline: true},
                {name: "Severity", value: $sev, inline: true},
                {name: "User", value: $user, inline: true},
                {name: "Time", value: $time, inline: false}
            ],
            footer: {text: "Server Monitor v1.0"}
        }]
    }')

# Send to Discord
curl -s -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "$DISCORD_WEBHOOK" > /dev/null 2>&1

# Local log backup
echo "[$(date)] [$SEVERITY] $ALERT_TITLE: $ALERT_MESSAGE" >> "$LOG_FILE"
SCRIPT

# File integrity monitor
cat > "${INSTALL_DIR}/bin/file-monitor.sh" << 'SCRIPT'
#!/bin/bash
# File Integrity Monitor using AIDE
source /opt/server-monitor/etc/config.env

AIDE_DB="/var/lib/aide/aide.db"
AIDE_NEW="/var/lib/aide/aide.db.new"

# Initialize AIDE if needed
if [[ ! -f "$AIDE_DB" ]]; then
    aide --init -c /etc/aide/aide.conf > /dev/null 2>&1
    mv "$AIDE_NEW" "$AIDE_DB" 2>/dev/null || true
    exit 0
fi

# Run check
CHANGES=$(aide --check -c /etc/aide/aide.conf 2>&1)
EXIT_CODE=$?

if [[ $EXIT_CODE -ne 0 ]] && [[ -n "$CHANGES" ]]; then
    # Parse changes
    ADDED=$(echo "$CHANGES" | grep -c "^Added:" || echo "0")
    REMOVED=$(echo "$CHANGES" | grep -c "^Removed:" || echo "0")
    CHANGED=$(echo "$CHANGES" | grep -c "^Changed:" || echo "0")
    
    MESSAGE="File integrity changes detected:\n"
    MESSAGE+="• Added: ${ADDED}\n"
    MESSAGE+="• Removed: ${REMOVED}\n"
    MESSAGE+="• Changed: ${CHANGED}\n\n"
    MESSAGE+="Run 'aide --check' for details"
    
    "${INSTALL_DIR}/bin/alert.sh" "file" "File Integrity Alert" "$MESSAGE" "high"
fi
SCRIPT

# Process monitor
cat > "${INSTALL_DIR}/bin/process-monitor.sh" << 'SCRIPT'
#!/bin/bash
# Process Execution Monitor
source /opt/server-monitor/etc/config.env

STATE_FILE="${INSTALL_DIR}/var/state/processes"
WHITELIST="${INSTALL_DIR}/etc/whitelist.conf"

# Get current processes with command
current_procs() {
    ps -eo pid,ppid,user,comm,args --no-headers 2>/dev/null | \
        awk '{print $1"|"$2"|"$3"|"$4"|"$5}'
}

# Load whitelist
load_whitelist() {
    grep -v '^#' "$WHITELIST" 2>/dev/null | grep -v '^$'
}

# Check if process is whitelisted
is_whitelisted() {
    local cmd="$1"
    while IFS= read -r pattern; do
        if echo "$cmd" | grep -qE "$pattern"; then
            return 0
        fi
    done < <(load_whitelist)
    return 1
}

# Initialize state
[[ ! -f "$STATE_FILE" ]] && current_procs > "$STATE_FILE"

# Find new processes
PREVIOUS=$(cat "$STATE_FILE")
CURRENT=$(current_procs)

# Detect new suspicious processes
while IFS='|' read -r pid ppid user comm args; do
    # Skip if in previous state
    echo "$PREVIOUS" | grep -q "^${pid}|" && continue
    
    # Skip whitelisted
    is_whitelisted "$args" && continue
    
    # Check for suspicious patterns
    SUSPICIOUS=0
    REASON=""
    
    # nohup detection
    if echo "$args" | grep -qE "nohup|&$"; then
        SUSPICIOUS=1
        REASON="Background/nohup process"
    fi
    
    # Hidden processes (starts with dot)
    if echo "$comm" | grep -qE "^\."; then
        SUSPICIOUS=1
        REASON="Hidden process name"
    fi
    
    # Crypto miners common names
    if echo "$comm" | grep -qiE "xmr|mine|kworker.*[0-9]{5}"; then
        SUSPICIOUS=1
        REASON="Potential crypto miner"
    fi
    
    # Reverse shells
    if echo "$args" | grep -qE "bash -i|/dev/tcp|nc.*-e|python.*pty"; then
        SUSPICIOUS=1
        REASON="Potential reverse shell"
    fi
    
    if [[ $SUSPICIOUS -eq 1 ]]; then
        MSG="Suspicious process detected:\n"
        MSG+="• PID: ${pid}\n"
        MSG+="• User: ${user}\n"
        MSG+="• Command: ${comm}\n"
        MSG+="• Reason: ${REASON}\n"
        MSG+="• Full: ${args:0:200}"
        
        "${INSTALL_DIR}/bin/alert.sh" "process" "Suspicious Process" "$MSG" "critical"
    fi
done <<< "$CURRENT"

# Update state
echo "$CURRENT" > "$STATE_FILE"
SCRIPT

# Network monitor
cat > "${INSTALL_DIR}/bin/network-monitor.sh" << 'SCRIPT'
#!/bin/bash
# Network Connection Monitor
source /opt/server-monitor/etc/config.env

STATE_FILE="${INSTALL_DIR}/var/state/connections"

# Known bad ports
BAD_PORTS="4444 5555 6666 31337 12345"

# Get established connections
get_connections() {
    ss -tupn state established 2>/dev/null | \
        awk 'NR>1 {print $5"|"$6"|"$7}' | sort -u
}

# Initialize
[[ ! -f "$STATE_FILE" ]] && get_connections > "$STATE_FILE"

PREVIOUS=$(cat "$STATE_FILE")
CURRENT=$(get_connections)

# Check for new suspicious connections
while IFS='|' read -r local remote process; do
    # Skip if existed before
    echo "$PREVIOUS" | grep -qF "$remote" && continue
    
    # Extract port
    PORT=$(echo "$remote" | grep -oE '[0-9]+$')
    
    SUSPICIOUS=0
    REASON=""
    
    # Check bad ports
    for bp in $BAD_PORTS; do
        if [[ "$PORT" == "$bp" ]]; then
            SUSPICIOUS=1
            REASON="Known malicious port"
            break
        fi
    done
    
    # Outbound to high ports from root processes
    if [[ "$PORT" -gt 50000 ]]; then
        # Might be suspicious
        SUSPICIOUS=1
        REASON="High port outbound connection"
    fi
    
    if [[ $SUSPICIOUS -eq 1 ]]; then
        MSG="Suspicious network connection:\n"
        MSG+="• Local: ${local}\n"
        MSG+="• Remote: ${remote}\n"
        MSG+="• Process: ${process}\n"
        MSG+="• Reason: ${REASON}"
        
        "${INSTALL_DIR}/bin/alert.sh" "network" "Network Anomaly" "$MSG" "high"
    fi
done <<< "$CURRENT"

echo "$CURRENT" > "$STATE_FILE"
SCRIPT

# SSH monitor
cat > "${INSTALL_DIR}/bin/ssh-monitor.sh" << 'SCRIPT'
#!/bin/bash
# SSH Activity Monitor
source /opt/server-monitor/etc/config.env

STATE_FILE="${INSTALL_DIR}/var/state/ssh_logins"
AUTH_LOG="/var/log/auth.log"

# Get last check timestamp
LAST_CHECK=0
[[ -f "$STATE_FILE" ]] && LAST_CHECK=$(cat "$STATE_FILE")

# Current timestamp
NOW=$(date +%s)
echo "$NOW" > "$STATE_FILE"

# Parse recent auth log entries
if [[ -f "$AUTH_LOG" ]]; then
    # Successful SSH logins
    grep "Accepted" "$AUTH_LOG" 2>/dev/null | tail -20 | while read -r line; do
        # Parse log entry
        TIMESTAMP=$(echo "$line" | awk '{print $1" "$2" "$3}')
        USER=$(echo "$line" | grep -oP 'for \K\w+')
        IP=$(echo "$line" | grep -oP 'from \K[0-9.]+')
        
        MSG="SSH Login Detected:\n"
        MSG+="• User: ${USER}\n"
        MSG+="• From: ${IP}\n"
        MSG+="• Time: ${TIMESTAMP}"
        
        "${INSTALL_DIR}/bin/alert.sh" "ssh" "SSH Login" "$MSG" "medium"
    done
    
    # Failed SSH attempts (brute force indicator)
    FAILED_COUNT=$(grep "Failed password" "$AUTH_LOG" 2>/dev/null | \
        awk -v t="$(date -d '5 minutes ago' '+%b %d %H:%M')" '$0 > t' | wc -l)
    
    if [[ $FAILED_COUNT -gt 10 ]]; then
        MSG="Brute force attack detected:\n"
        MSG+="• Failed attempts: ${FAILED_COUNT} in 5 minutes"
        
        "${INSTALL_DIR}/bin/alert.sh" "ssh" "Brute Force Attack" "$MSG" "critical"
    fi
    
    # Privilege escalation (sudo/su)
    grep -E "sudo:|su\[" "$AUTH_LOG" 2>/dev/null | tail -5 | while read -r line; do
        if echo "$line" | grep -qv "session opened"; then
            continue
        fi
        USER=$(echo "$line" | grep -oP 'for user \K\w+|by \K\w+')
        
        MSG="Privilege escalation:\n"
        MSG+="• User: ${USER}\n"
        MSG+="• Details: ${line:0:150}"
        
        "${INSTALL_DIR}/bin/alert.sh" "privesc" "Privilege Escalation" "$MSG" "high"
    done
fi
SCRIPT

# Watchdog (monitors the monitors)
cat > "${INSTALL_DIR}/bin/watchdog.sh" << 'SCRIPT'
#!/bin/bash
# Watchdog - Monitors the monitoring system
source /opt/server-monitor/etc/config.env

SERVICES=("server-file-monitor" "server-process-monitor" "server-network-monitor" "server-ssh-monitor")

for svc in "${SERVICES[@]}"; do
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        MSG="Monitoring service down:\n"
        MSG+="• Service: ${svc}\n"
        MSG+="• Action: Attempting restart"
        
        "${INSTALL_DIR}/bin/alert.sh" "watchdog" "Service Down" "$MSG" "critical"
        
        # Attempt restart
        systemctl restart "$svc" 2>/dev/null || true
    fi
done

# Check if auditd is running
if ! systemctl is-active --quiet auditd; then
    MSG="Auditd service stopped!\n"
    MSG+="• This may indicate tampering"
    
    "${INSTALL_DIR}/bin/alert.sh" "watchdog" "Auditd Down" "$MSG" "critical"
    systemctl restart auditd 2>/dev/null || true
fi

# Check if audit rules are intact
RULE_COUNT=$(auditctl -l 2>/dev/null | wc -l)
if [[ $RULE_COUNT -lt 5 ]]; then
    MSG="Audit rules may have been cleared!\n"
    MSG+="• Expected: 10+ rules\n"
    MSG+="• Found: ${RULE_COUNT}"
    
    "${INSTALL_DIR}/bin/alert.sh" "watchdog" "Audit Rules Modified" "$MSG" "critical"
fi

# Check script integrity
SCRIPTS="${INSTALL_DIR}/bin"
for script in "$SCRIPTS"/*.sh; do
    if [[ ! -f "$script" ]]; then
        MSG="Monitoring script missing:\n"
        MSG+="• Script: ${script}"
        
        "${INSTALL_DIR}/bin/alert.sh" "watchdog" "Script Deleted" "$MSG" "critical"
    fi
done
SCRIPT

# Set permissions
chmod 700 "${INSTALL_DIR}/bin"/*.sh

#-------------------------------------------------------------------------------
# Create systemd services
#-------------------------------------------------------------------------------
log "Creating systemd services..."

# File monitor timer
cat > /etc/systemd/system/server-file-monitor.service << EOF
[Unit]
Description=File Integrity Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/bin/file-monitor.sh
StandardOutput=journal
StandardError=journal
EOF

cat > /etc/systemd/system/server-file-monitor.timer << EOF
[Unit]
Description=File Integrity Monitor Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Process monitor service (continuous)
cat > /etc/systemd/system/server-process-monitor.service << EOF
[Unit]
Description=Process Execution Monitor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do ${INSTALL_DIR}/bin/process-monitor.sh; sleep 30; done'
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Network monitor service
cat > /etc/systemd/system/server-network-monitor.service << EOF
[Unit]
Description=Network Connection Monitor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do ${INSTALL_DIR}/bin/network-monitor.sh; sleep 60; done'
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# SSH monitor service
cat > /etc/systemd/system/server-ssh-monitor.service << EOF
[Unit]
Description=SSH Activity Monitor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do ${INSTALL_DIR}/bin/ssh-monitor.sh; sleep 30; done'
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Watchdog service
cat > /etc/systemd/system/server-watchdog.service << EOF
[Unit]
Description=Server Monitor Watchdog
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do ${INSTALL_DIR}/bin/watchdog.sh; sleep 120; done'
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

#-------------------------------------------------------------------------------
# Configure auditd
#-------------------------------------------------------------------------------
log "Configuring auditd..."

cat > /etc/audit/rules.d/server-monitor.rules << 'EOF'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (2 = panic, 1 = printk, 0 = silent)
-f 1

# Monitor /etc changes
-w /etc -p wa -k etc_changes

# Monitor binary directories
-w /usr/bin -p wa -k bin_changes
-w /usr/sbin -p wa -k sbin_changes
-w /bin -p wa -k bin_changes
-w /sbin -p wa -k sbin_changes

# Monitor cron
-w /etc/crontab -p wa -k cron_changes
-w /etc/cron.d -p wa -k cron_changes
-w /var/spool/cron -p wa -k cron_changes

# Monitor systemd
-w /etc/systemd -p wa -k systemd_changes
-w /lib/systemd -p wa -k systemd_changes

# Monitor SSH
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /root/.ssh -p wa -k ssh_keys

# Monitor passwd/shadow
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Monitor this monitoring system
-w /opt/server-monitor -p wa -k monitor_changes

# Process execution
-a always,exit -F arch=b64 -S execve -k exec_log

# Network connections (socket creation)
-a always,exit -F arch=b64 -S socket -k socket_create

# Audit rule modifications (self-protection)
-w /etc/audit -p wa -k audit_changes
-w /etc/audit/rules.d -p wa -k audit_rules_changes

# Make rules immutable (requires reboot to change)
-e 2
EOF

# Restart auditd
service auditd restart || systemctl restart auditd

#-------------------------------------------------------------------------------
# Configure AIDE
#-------------------------------------------------------------------------------
log "Configuring AIDE..."

# AIDE config already exists, just customize
if [[ -f /etc/aide/aide.conf ]]; then
    # Add custom monitoring paths
    cat >> /etc/aide/aide.conf << 'EOF'

# Custom monitoring
/opt/server-monitor CONTENT_EX
EOF
fi

# Initialize AIDE database
log "Initializing AIDE database (this may take a while)..."
aide --init -c /etc/aide/aide.conf > /dev/null 2>&1 || true
[[ -f /var/lib/aide/aide.db.new ]] && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

#-------------------------------------------------------------------------------
# Configure fail2ban
#-------------------------------------------------------------------------------
log "Configuring fail2ban..."

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400
EOF

systemctl enable fail2ban
systemctl restart fail2ban

#-------------------------------------------------------------------------------
# Configure rkhunter
#-------------------------------------------------------------------------------
log "Configuring rkhunter..."

rkhunter --update > /dev/null 2>&1 || true
rkhunter --propupd > /dev/null 2>&1 || true

#-------------------------------------------------------------------------------
# Enable services
#-------------------------------------------------------------------------------
log "Enabling services..."

systemctl daemon-reload
systemctl enable --now server-file-monitor.timer
systemctl enable --now server-process-monitor
systemctl enable --now server-network-monitor
systemctl enable --now server-ssh-monitor
systemctl enable --now server-watchdog

#-------------------------------------------------------------------------------
# Tamper protection
#-------------------------------------------------------------------------------
log "Applying tamper protection..."

# Make scripts immutable
chattr +i "${INSTALL_DIR}/bin"/*.sh 2>/dev/null || warn "chattr not available"
chattr +i "${INSTALL_DIR}/etc/config.env" 2>/dev/null || true

# Protect systemd units
chattr +i /etc/systemd/system/server-*.service 2>/dev/null || true
chattr +i /etc/systemd/system/server-*.timer 2>/dev/null || true

#-------------------------------------------------------------------------------
# Send test alert
#-------------------------------------------------------------------------------
log "Sending test alert..."
"${INSTALL_DIR}/bin/alert.sh" "test" "System Online" "Server monitoring installed and active on ${HOSTNAME}" "low"

#-------------------------------------------------------------------------------
# Done
#-------------------------------------------------------------------------------
echo ""
log "Installation complete!"
echo ""
echo "Verification:"
echo "  systemctl status server-process-monitor"
echo "  systemctl status server-watchdog"
echo "  journalctl -u server-process-monitor -f"
echo ""
echo "To update AIDE baseline after legitimate changes:"
echo "  aide --update && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
echo ""
