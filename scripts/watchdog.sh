#!/bin/bash
#===============================================================================
# WATCHDOG - INTELLIGENT SERVICE MONITOR
# Automatically detects and monitors important services on your server
#===============================================================================

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/opt/server-monitor/etc/config.env}"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

INSTALL_DIR="${INSTALL_DIR:-/opt/server-monitor}"
ALERT_SCRIPT="${INSTALL_DIR}/bin/alert.sh"
STATE_DIR="${INSTALL_DIR}/var/state"
SERVICES_STATE="${STATE_DIR}/watched_services"

mkdir -p "$STATE_DIR"

#-------------------------------------------------------------------------------
# Internal monitoring services (always monitor these)
#-------------------------------------------------------------------------------
MONITOR_SERVICES=(
    "server-process-monitor"
    "server-network-monitor"
    "server-ssh-monitor"
)

#-------------------------------------------------------------------------------
# Auto-detect important services running on this server
#-------------------------------------------------------------------------------
detect_important_services() {
    local services=()
    
    # Web servers
    systemctl is-enabled nginx 2>/dev/null && services+=("nginx")
    systemctl is-enabled apache2 2>/dev/null && services+=("apache2")
    systemctl is-enabled httpd 2>/dev/null && services+=("httpd")
    systemctl is-enabled caddy 2>/dev/null && services+=("caddy")
    
    # Databases
    systemctl is-enabled mysql 2>/dev/null && services+=("mysql")
    systemctl is-enabled mariadb 2>/dev/null && services+=("mariadb")
    systemctl is-enabled postgresql 2>/dev/null && services+=("postgresql")
    systemctl is-enabled mongod 2>/dev/null && services+=("mongod")
    systemctl is-enabled redis 2>/dev/null && services+=("redis")
    systemctl is-enabled redis-server 2>/dev/null && services+=("redis-server")
    
    # Application servers
    systemctl is-enabled docker 2>/dev/null && services+=("docker")
    systemctl is-enabled containerd 2>/dev/null && services+=("containerd")
    systemctl is-enabled pm2-* 2>/dev/null && services+=("pm2")
    
    # Security services
    systemctl is-enabled auditd 2>/dev/null && services+=("auditd")
    systemctl is-enabled fail2ban 2>/dev/null && services+=("fail2ban")
    systemctl is-enabled ufw 2>/dev/null && services+=("ufw")
    systemctl is-enabled firewalld 2>/dev/null && services+=("firewalld")
    
    # Other common services
    systemctl is-enabled cron 2>/dev/null && services+=("cron")
    systemctl is-enabled sshd 2>/dev/null && services+=("sshd")
    systemctl is-enabled ssh 2>/dev/null && services+=("ssh")
    
    echo "${services[@]}"
}

#-------------------------------------------------------------------------------
# Get friendly service description
#-------------------------------------------------------------------------------
get_service_description() {
    local svc="$1"
    case "$svc" in
        nginx|apache2|httpd|caddy) echo "🌐 Web Server" ;;
        mysql|mariadb|postgresql|mongod) echo "🗄️ Database" ;;
        redis|redis-server) echo "⚡ Cache/Queue" ;;
        docker|containerd) echo "🐳 Container Runtime" ;;
        auditd|fail2ban|ufw|firewalld) echo "🔒 Security Service" ;;
        sshd|ssh) echo "🔑 SSH Server" ;;
        cron) echo "⏰ Scheduler" ;;
        *) echo "⚙️ Service" ;;
    esac
}

#-------------------------------------------------------------------------------
# Get severity based on service type
#-------------------------------------------------------------------------------
get_service_severity() {
    local svc="$1"
    case "$svc" in
        nginx|apache2|httpd|caddy) echo "critical" ;;  # Web down = site down
        mysql|mariadb|postgresql|mongod) echo "critical" ;;  # DB down = app down
        docker) echo "critical" ;;  # Containers may die
        sshd|ssh) echo "critical" ;;  # Can't access server!
        auditd|fail2ban) echo "high" ;;  # Security degraded
        redis|redis-server) echo "high" ;;  # Performance impact
        *) echo "medium" ;;
    esac
}

#-------------------------------------------------------------------------------
# Check internal monitoring services
#-------------------------------------------------------------------------------
for svc in "${MONITOR_SERVICES[@]}"; do
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        MSG="🐕 Monitoring service stopped!

**Service:** \`${svc}\`
**Status:** $(systemctl is-active "$svc" 2>/dev/null || echo "stopped")
**Action:** Attempting automatic restart..."
        
        "$ALERT_SCRIPT" "watchdog" "Monitor Down" "$MSG" "critical"
        
        # Attempt restart
        systemctl restart "$svc" 2>/dev/null || true
        sleep 2
        
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            "$ALERT_SCRIPT" "watchdog" "Monitor Recovered" "✅ Service \`${svc}\` restarted successfully" "low"
        fi
    fi
done

#-------------------------------------------------------------------------------
# Check auto-detected important services
#-------------------------------------------------------------------------------
IMPORTANT_SERVICES=$(detect_important_services)

for svc in $IMPORTANT_SERVICES; do
    STATE_FILE="${STATE_DIR}/svc_${svc}"
    WAS_RUNNING=1
    [[ -f "$STATE_FILE" ]] && WAS_RUNNING=$(cat "$STATE_FILE")
    
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        # Service is running
        IS_RUNNING=1
        
        # If it was down before, alert that it's back
        if [[ "$WAS_RUNNING" == "0" ]]; then
            DESC=$(get_service_description "$svc")
            MSG="${DESC} is back online!

**Service:** \`${svc}\`
**Status:** ✅ Running"
            
            "$ALERT_SCRIPT" "watchdog" "Service Recovered" "$MSG" "low"
        fi
    else
        # Service is NOT running
        IS_RUNNING=0
        
        # Only alert if it was running before (avoid spam on boot)
        if [[ "$WAS_RUNNING" == "1" ]]; then
            DESC=$(get_service_description "$svc")
            SEVERITY=$(get_service_severity "$svc")
            
            MSG="${DESC} has stopped!

**Service:** \`${svc}\`
**Status:** ❌ Not running
**Impact:** $(case "$SEVERITY" in
    critical) echo "⚠️ IMMEDIATE ACTION REQUIRED" ;;
    high) echo "Service functionality degraded" ;;
    *) echo "May affect system operations" ;;
esac)

_Check with:_ \`sudo systemctl status ${svc}\`"
            
            "$ALERT_SCRIPT" "watchdog" "Service Down: ${svc}" "$MSG" "$SEVERITY"
        fi
    fi
    
    echo "$IS_RUNNING" > "$STATE_FILE"
done
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
