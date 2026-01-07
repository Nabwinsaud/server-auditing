#!/bin/bash
#===============================================================================
# WATCHDOG - MONITORS THE MONITORING SYSTEM
# Ensures all monitoring services are running and restarts if needed
#===============================================================================

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/opt/server-monitor/etc/config.env}"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

INSTALL_DIR="${INSTALL_DIR:-/opt/server-monitor}"
ALERT_SCRIPT="${INSTALL_DIR}/bin/alert.sh"

#-------------------------------------------------------------------------------
# Services to monitor
#-------------------------------------------------------------------------------
MONITOR_SERVICES=(
    "server-process-monitor"
    "server-network-monitor"
    "server-ssh-monitor"
)

CRITICAL_SERVICES=(
    "auditd"
    "fail2ban"
)

#-------------------------------------------------------------------------------
# Check monitoring services
#-------------------------------------------------------------------------------
for svc in "${MONITOR_SERVICES[@]}"; do
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        MSG="Monitoring service down:\n"
        MSG+="• **Service:** ${svc}\n"
        MSG+="• **Status:** $(systemctl is-active "$svc" 2>/dev/null || echo "unknown")\n"
        MSG+="• **Action:** Attempting automatic restart"
        
        "$ALERT_SCRIPT" "watchdog" "Monitor Service Down" "$MSG" "critical"
        
        # Attempt restart
        systemctl restart "$svc" 2>/dev/null || true
        sleep 2
        
        # Verify restart
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            "$ALERT_SCRIPT" "watchdog" "Service Recovered" "Service ${svc} restarted successfully" "low"
        else
            "$ALERT_SCRIPT" "watchdog" "Restart Failed" "Failed to restart ${svc} - manual intervention required" "critical"
        fi
    fi
done

#-------------------------------------------------------------------------------
# Check critical security services
#-------------------------------------------------------------------------------
for svc in "${CRITICAL_SERVICES[@]}"; do
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        MSG="Critical security service stopped:\n"
        MSG+="• **Service:** ${svc}\n"
        MSG+="• **Impact:** Security monitoring degraded\n"
        MSG+="• **Action:** Attempting restart"
        
        "$ALERT_SCRIPT" "watchdog" "Security Service Down" "$MSG" "critical"
        
        systemctl restart "$svc" 2>/dev/null || true
    fi
done

#-------------------------------------------------------------------------------
# Check file monitor timer
#-------------------------------------------------------------------------------
if ! systemctl is-active --quiet server-file-monitor.timer 2>/dev/null; then
    MSG="File integrity monitor timer stopped"
    "$ALERT_SCRIPT" "watchdog" "Timer Stopped" "$MSG" "high"
    systemctl restart server-file-monitor.timer 2>/dev/null || true
fi

#-------------------------------------------------------------------------------
# Check audit rules integrity
#-------------------------------------------------------------------------------
RULE_COUNT=$(auditctl -l 2>/dev/null | wc -l)
EXPECTED_MIN_RULES=10

if [[ $RULE_COUNT -lt $EXPECTED_MIN_RULES ]]; then
    MSG="Audit rules may have been tampered with:\n"
    MSG+="• **Expected:** >${EXPECTED_MIN_RULES} rules\n"
    MSG+="• **Found:** ${RULE_COUNT} rules\n"
    MSG+="• **Action:** Reload audit rules"
    
    "$ALERT_SCRIPT" "watchdog" "Audit Rules Modified" "$MSG" "critical"
    
    # Attempt to reload rules
    if [[ -f /etc/audit/rules.d/server-monitor.rules ]]; then
        augenrules --load 2>/dev/null || true
    fi
fi

#-------------------------------------------------------------------------------
# Check script integrity
#-------------------------------------------------------------------------------
SCRIPTS_DIR="${INSTALL_DIR}/bin"
EXPECTED_SCRIPTS=(
    "alert.sh"
    "file-monitor.sh"
    "process-monitor.sh"
    "network-monitor.sh"
    "ssh-monitor.sh"
    "watchdog.sh"
)

for script in "${EXPECTED_SCRIPTS[@]}"; do
    if [[ ! -f "${SCRIPTS_DIR}/${script}" ]]; then
        MSG="Monitoring script deleted:\n"
        MSG+="• **Script:** ${script}\n"
        MSG+="• **Path:** ${SCRIPTS_DIR}/${script}\n"
        MSG+="• **Impact:** Monitoring capability degraded"
        
        "$ALERT_SCRIPT" "watchdog" "Script Deleted" "$MSG" "critical"
    fi
done

#-------------------------------------------------------------------------------
# Check config file
#-------------------------------------------------------------------------------
if [[ ! -f "${INSTALL_DIR}/etc/config.env" ]]; then
    MSG="Configuration file missing:\n"
    MSG+="• **File:** ${INSTALL_DIR}/etc/config.env\n"
    MSG+="• **Impact:** Alerts may fail"
    
    "$ALERT_SCRIPT" "watchdog" "Config Missing" "$MSG" "critical"
fi

#-------------------------------------------------------------------------------
# Check disk space (for logs)
#-------------------------------------------------------------------------------
DISK_USAGE=$(df "${INSTALL_DIR}" 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')
if [[ -n "$DISK_USAGE" ]] && [[ $DISK_USAGE -gt 90 ]]; then
    MSG="Disk space critical:\n"
    MSG+="• **Usage:** ${DISK_USAGE}%\n"
    MSG+="• **Impact:** Logs may fail to write"
    
    "$ALERT_SCRIPT" "watchdog" "Disk Space Critical" "$MSG" "high"
fi

#-------------------------------------------------------------------------------
# Heartbeat (optional - uncomment to enable)
#-------------------------------------------------------------------------------
# Sends periodic "still alive" message
# HEARTBEAT_FILE="${INSTALL_DIR}/var/state/heartbeat"
# HEARTBEAT_INTERVAL=3600  # 1 hour
# 
# NOW=$(date +%s)
# LAST_HEARTBEAT=0
# [[ -f "$HEARTBEAT_FILE" ]] && LAST_HEARTBEAT=$(cat "$HEARTBEAT_FILE")
# 
# if (( NOW - LAST_HEARTBEAT > HEARTBEAT_INTERVAL )); then
#     "$ALERT_SCRIPT" "watchdog" "Heartbeat" "Server monitor is running normally" "info"
#     echo "$NOW" > "$HEARTBEAT_FILE"
# fi
