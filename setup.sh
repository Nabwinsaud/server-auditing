#!/bin/bash
#===============================================================================
# SERVER MONITOR - ONE-LINE INSTALLER
# Usage: curl -sSL https://raw.githubusercontent.com/Nabwinsaud/server-auditing/main/setup.sh | sudo DISCORD_WEBHOOK="your-webhook" bash
#===============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

#-------------------------------------------------------------------------------
# Banner
#-------------------------------------------------------------------------------
echo -e "${CYAN}"
cat << 'EOF'
  ____                           __  __             _ _             
 / ___|  ___ _ ____   _____ _ __|  \/  | ___  _ __ (_) |_ ___  _ __ 
 \___ \ / _ \ '__\ \ / / _ \ '__| |\/| |/ _ \| '_ \| | __/ _ \| '__|
  ___) |  __/ |   \ V /  __/ |  | |  | | (_) | | | | | || (_) | |   
 |____/ \___|_|    \_/ \___|_|  |_|  |_|\___/|_| |_|_|\__\___/|_|   
                                                                     
EOF
echo -e "${NC}"
echo "Intrusion Detection & Alert System"
echo "===================================="
echo ""

#-------------------------------------------------------------------------------
# Pre-flight checks
#-------------------------------------------------------------------------------
[[ $EUID -ne 0 ]] && error "Must run as root. Use: sudo DISCORD_WEBHOOK=\"your-webhook\" bash"

if [[ -z "${DISCORD_WEBHOOK:-}" ]]; then
    echo -e "${RED}ERROR: DISCORD_WEBHOOK not set${NC}"
    echo ""
    echo "Usage:"
    echo "  curl -sSL https://raw.githubusercontent.com/Nabwinsaud/server-auditing/main/setup.sh | sudo DISCORD_WEBHOOK=\"https://discord.com/api/webhooks/xxx/yyy\" bash"
    echo ""
    exit 1
fi

# Validate webhook format
if [[ ! "$DISCORD_WEBHOOK" =~ ^https://discord\.com/api/webhooks/ ]]; then
    error "Invalid Discord webhook URL format"
fi

REPO_URL="https://raw.githubusercontent.com/Nabwinsaud/server-auditing/main"
INSTALL_DIR="/opt/server-monitor"
HOSTNAME=$(hostname)

info "Installing on: ${HOSTNAME}"
info "Webhook: ${DISCORD_WEBHOOK:0:50}..."
echo ""

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

# Install packages with options to avoid any interactive prompts
PACKAGES="auditd audispd-plugins aide fail2ban rkhunter chkrootkit inotify-tools jq curl ufw"
for pkg in $PACKAGES; do
    if ! dpkg -l "$pkg" &>/dev/null; then
        apt-get install -y -qq \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            "$pkg" 2>/dev/null || warn "Failed to install $pkg"
    fi
done

#-------------------------------------------------------------------------------
# Create directory structure
#-------------------------------------------------------------------------------
log "Creating directory structure..."
mkdir -p "${INSTALL_DIR}"/{bin,etc,var/state,var/cache,logs}

#-------------------------------------------------------------------------------
# Download scripts from GitHub
#-------------------------------------------------------------------------------
log "Downloading monitoring scripts..."

SCRIPTS=(
    "scripts/alert.sh:bin/alert.sh"
    "scripts/file-monitor.sh:bin/file-monitor.sh"
    "scripts/process-monitor.sh:bin/process-monitor.sh"
    "scripts/network-monitor.sh:bin/network-monitor.sh"
    "scripts/ssh-monitor.sh:bin/ssh-monitor.sh"
    "scripts/watchdog.sh:bin/watchdog.sh"
    "scripts/rootkit-scan.sh:bin/rootkit-scan.sh"
    "etc/whitelist.conf:etc/whitelist.conf"
    "audit/server-monitor.rules:audit-rules.tmp"
)

for mapping in "${SCRIPTS[@]}"; do
    src="${mapping%%:*}"
    dst="${mapping##*:}"
    curl -sSL "${REPO_URL}/${src}" -o "${INSTALL_DIR}/${dst}" || warn "Failed to download ${src}"
done

chmod 700 "${INSTALL_DIR}/bin"/*.sh

#-------------------------------------------------------------------------------
# Create configuration
#-------------------------------------------------------------------------------
log "Creating configuration..."

# Get timezone from environment or use UTC
TIMEZONE="${TIMEZONE:-UTC}"

cat > "${INSTALL_DIR}/etc/config.env" << EOF
# Server Monitor Configuration
# SECURITY: Keep this file protected (chmod 600)
DISCORD_WEBHOOK="${DISCORD_WEBHOOK}"
HOSTNAME="${HOSTNAME}"
INSTALL_DIR="${INSTALL_DIR}"
TIMEZONE="${TIMEZONE}"
RATE_LIMIT_SECONDS=300
LOG_FILE="${INSTALL_DIR}/logs/monitor.log"
EOF
chmod 600 "${INSTALL_DIR}/etc/config.env"

# Create dedup directory for duplicate prevention
mkdir -p "${INSTALL_DIR}/var/dedup"

#-------------------------------------------------------------------------------
# Install audit rules
#-------------------------------------------------------------------------------
log "Configuring auditd..."
if [[ -f "${INSTALL_DIR}/audit-rules.tmp" ]]; then
    mv "${INSTALL_DIR}/audit-rules.tmp" /etc/audit/rules.d/server-monitor.rules
    service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
fi

#-------------------------------------------------------------------------------
# Create systemd services
#-------------------------------------------------------------------------------
log "Creating systemd services..."

# Process monitor
cat > /etc/systemd/system/server-process-monitor.service << EOF
[Unit]
Description=Process Execution Monitor
After=network.target auditd.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do ${INSTALL_DIR}/bin/process-monitor.sh; sleep 30; done'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Network monitor
cat > /etc/systemd/system/server-network-monitor.service << EOF
[Unit]
Description=Network Connection Monitor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do ${INSTALL_DIR}/bin/network-monitor.sh; sleep 60; done'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# SSH monitor
cat > /etc/systemd/system/server-ssh-monitor.service << EOF
[Unit]
Description=SSH Activity Monitor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do ${INSTALL_DIR}/bin/ssh-monitor.sh; sleep 30; done'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Watchdog
cat > /etc/systemd/system/server-watchdog.service << EOF
[Unit]
Description=Server Monitor Watchdog
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do ${INSTALL_DIR}/bin/watchdog.sh; sleep 120; done'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# File monitor (timer-based)
cat > /etc/systemd/system/server-file-monitor.service << EOF
[Unit]
Description=File Integrity Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/bin/file-monitor.sh
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

# Rootkit scan (daily)
cat > /etc/systemd/system/server-rootkit-scan.service << EOF
[Unit]
Description=Rootkit Scanner
After=network.target

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/bin/rootkit-scan.sh
EOF

cat > /etc/systemd/system/server-rootkit-scan.timer << EOF
[Unit]
Description=Daily Rootkit Scan

[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

#-------------------------------------------------------------------------------
# Configure AIDE
#-------------------------------------------------------------------------------
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

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400
EOF

systemctl enable fail2ban --now 2>/dev/null || true

#-------------------------------------------------------------------------------
# Configure rkhunter
#-------------------------------------------------------------------------------
log "Updating rkhunter..."
rkhunter --update > /dev/null 2>&1 || true
rkhunter --propupd > /dev/null 2>&1 || true

#-------------------------------------------------------------------------------
# Enable services
#-------------------------------------------------------------------------------
log "Enabling services..."
systemctl daemon-reload
systemctl enable --now server-process-monitor
systemctl enable --now server-network-monitor
systemctl enable --now server-ssh-monitor
systemctl enable --now server-watchdog
systemctl enable --now server-file-monitor.timer
systemctl enable --now server-rootkit-scan.timer

#-------------------------------------------------------------------------------
# Apply tamper protection
#-------------------------------------------------------------------------------
log "Applying tamper protection..."
chattr +i "${INSTALL_DIR}/bin"/*.sh 2>/dev/null || warn "chattr not available (ext4 required)"
chattr +i "${INSTALL_DIR}/etc/config.env" 2>/dev/null || true

#-------------------------------------------------------------------------------
# Send test alert
#-------------------------------------------------------------------------------
log "Sending test alert to Discord..."
"${INSTALL_DIR}/bin/alert.sh" "test" "🎉 Server Monitor Installed" "Monitoring is now active on ${HOSTNAME}" "low"

#-------------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Installation Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Monitoring services:"
systemctl is-active server-process-monitor && echo "  ✓ Process monitor"
systemctl is-active server-network-monitor && echo "  ✓ Network monitor"
systemctl is-active server-ssh-monitor && echo "  ✓ SSH monitor"
systemctl is-active server-watchdog && echo "  ✓ Watchdog"
systemctl is-active server-file-monitor.timer && echo "  ✓ File integrity (timer)"
systemctl is-active server-rootkit-scan.timer && echo "  ✓ Rootkit scan (daily)"
echo ""
echo "Commands:"
echo "  journalctl -u server-process-monitor -f  # View logs"
echo "  ${INSTALL_DIR}/bin/alert.sh test \"Title\" \"Message\" high  # Test alert"
echo ""
echo "Uninstall:"
echo "  curl -sSL ${REPO_URL}/uninstall.sh | sudo bash"
echo ""
