#!/bin/bash
#===============================================================================
# UNINSTALL SERVER MONITOR
# Run as root: sudo ./uninstall.sh
#===============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${RED}[!]${NC} $1"; }

[[ $EUID -ne 0 ]] && { echo "Must run as root"; exit 1; }

INSTALL_DIR="/opt/server-monitor"

log "Stopping services..."
systemctl stop server-file-monitor.timer 2>/dev/null || true
systemctl stop server-rootkit-scan.timer 2>/dev/null || true
systemctl stop server-process-monitor 2>/dev/null || true
systemctl stop server-network-monitor 2>/dev/null || true
systemctl stop server-ssh-monitor 2>/dev/null || true
systemctl stop server-watchdog 2>/dev/null || true

log "Disabling services..."
systemctl disable server-file-monitor.timer 2>/dev/null || true
systemctl disable server-rootkit-scan.timer 2>/dev/null || true
systemctl disable server-process-monitor 2>/dev/null || true
systemctl disable server-network-monitor 2>/dev/null || true
systemctl disable server-ssh-monitor 2>/dev/null || true
systemctl disable server-watchdog 2>/dev/null || true

log "Removing immutability..."
chattr -i "${INSTALL_DIR}/bin"/*.sh 2>/dev/null || true
chattr -i "${INSTALL_DIR}/etc/config.env" 2>/dev/null || true
chattr -i /etc/systemd/system/server-*.service 2>/dev/null || true
chattr -i /etc/systemd/system/server-*.timer 2>/dev/null || true

log "Removing systemd units..."
rm -f /etc/systemd/system/server-*.service
rm -f /etc/systemd/system/server-*.timer
systemctl daemon-reload

log "Removing audit rules..."
rm -f /etc/audit/rules.d/server-monitor.rules
service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true

log "Removing installation directory..."
rm -rf "${INSTALL_DIR}"

log "Uninstall complete"
echo ""
warn "Note: auditd, AIDE, fail2ban, rkhunter packages are still installed"
echo "To remove them: apt remove auditd aide fail2ban rkhunter"
