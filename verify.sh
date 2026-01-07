#!/bin/bash
#===============================================================================
# SERVER INTRUSION DETECTION SYSTEM - VERIFICATION
# Run as root: sudo ./verify.sh
#===============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[✓]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

echo "=========================================="
echo " Server Monitor Verification"
echo "=========================================="
echo ""

#-------------------------------------------------------------------------------
# Check services
#-------------------------------------------------------------------------------
echo "1. Checking services..."

SERVICES=(
    "server-process-monitor"
    "server-network-monitor"
    "server-ssh-monitor"
    "server-watchdog"
    "auditd"
    "fail2ban"
)

for svc in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        pass "$svc is running"
    else
        fail "$svc is NOT running"
    fi
done

# Timer
if systemctl is-active --quiet server-file-monitor.timer 2>/dev/null; then
    pass "server-file-monitor.timer is active"
else
    fail "server-file-monitor.timer is NOT active"
fi

echo ""

#-------------------------------------------------------------------------------
# Check files
#-------------------------------------------------------------------------------
echo "2. Checking files..."

INSTALL_DIR="/opt/server-monitor"
FILES=(
    "${INSTALL_DIR}/bin/alert.sh"
    "${INSTALL_DIR}/bin/file-monitor.sh"
    "${INSTALL_DIR}/bin/process-monitor.sh"
    "${INSTALL_DIR}/bin/network-monitor.sh"
    "${INSTALL_DIR}/bin/ssh-monitor.sh"
    "${INSTALL_DIR}/bin/watchdog.sh"
    "${INSTALL_DIR}/etc/config.env"
)

for f in "${FILES[@]}"; do
    if [[ -f "$f" ]]; then
        pass "$f exists"
    else
        fail "$f missing"
    fi
done

echo ""

#-------------------------------------------------------------------------------
# Check immutability
#-------------------------------------------------------------------------------
echo "3. Checking immutability (tamper protection)..."

IMMUTABLE_COUNT=0
for script in "${INSTALL_DIR}/bin"/*.sh; do
    if lsattr "$script" 2>/dev/null | grep -q '^....i'; then
        IMMUTABLE_COUNT=$((IMMUTABLE_COUNT + 1))
    fi
done

if [[ $IMMUTABLE_COUNT -gt 0 ]]; then
    pass "$IMMUTABLE_COUNT scripts are immutable"
else
    warn "Scripts are NOT immutable (chattr +i not applied)"
fi

echo ""

#-------------------------------------------------------------------------------
# Check auditd rules
#-------------------------------------------------------------------------------
echo "4. Checking audit rules..."

RULE_COUNT=$(auditctl -l 2>/dev/null | wc -l)
if [[ $RULE_COUNT -gt 5 ]]; then
    pass "Audit rules loaded: $RULE_COUNT rules"
else
    fail "Audit rules may be incomplete: only $RULE_COUNT rules"
fi

# Check for immutable mode
if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
    pass "Audit rules are immutable (requires reboot to change)"
else
    warn "Audit rules are NOT in immutable mode"
fi

echo ""

#-------------------------------------------------------------------------------
# Check AIDE
#-------------------------------------------------------------------------------
echo "5. Checking AIDE..."

if [[ -f /var/lib/aide/aide.db ]]; then
    pass "AIDE database exists"
else
    fail "AIDE database not initialized"
fi

echo ""

#-------------------------------------------------------------------------------
# Check Discord webhook
#-------------------------------------------------------------------------------
echo "6. Checking Discord webhook..."

if grep -q "DISCORD_WEBHOOK=" "${INSTALL_DIR}/etc/config.env" 2>/dev/null; then
    WEBHOOK=$(grep "DISCORD_WEBHOOK=" "${INSTALL_DIR}/etc/config.env" | cut -d'"' -f2)
    if [[ "$WEBHOOK" == *"discord.com/api/webhooks"* ]]; then
        pass "Discord webhook configured"
    else
        fail "Discord webhook looks invalid"
    fi
else
    fail "Discord webhook not configured"
fi

echo ""

#-------------------------------------------------------------------------------
# Test alert
#-------------------------------------------------------------------------------
echo "7. Testing alert (check Discord)..."

"${INSTALL_DIR}/bin/alert.sh" "test" "Verification Test" "This is a test alert from verify.sh" "low"
pass "Test alert sent (check Discord)"

echo ""

#-------------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------------
echo "=========================================="
echo " Verification Complete"
echo "=========================================="
echo ""
echo "Commands to monitor:"
echo "  journalctl -u server-process-monitor -f"
echo "  journalctl -u server-watchdog -f"
echo "  ausearch -k exec_log | tail"
echo "  tail -f ${INSTALL_DIR}/logs/monitor.log"
echo ""
echo "To test file integrity:"
echo "  touch /etc/test-file && aide --check"
echo ""
echo "To simulate attack (careful!):"
echo "  nohup sleep 300 &"
echo ""
