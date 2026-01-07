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

mkdir -p "$STATE_DIR"

#-------------------------------------------------------------------------------
# Internal monitoring services
#-------------------------------------------------------------------------------
MONITOR_SERVICES=(
    "server-process-monitor"
    "server-network-monitor"
    "server-ssh-monitor"
)

#-------------------------------------------------------------------------------
# Auto-detect important services
#-------------------------------------------------------------------------------
detect_important_services() {
    local services=()
    
    # Web servers
    systemctl is-enabled nginx 2>/dev/null | grep -q "enabled" && services+=("nginx")
    systemctl is-enabled apache2 2>/dev/null | grep -q "enabled" && services+=("apache2")
    systemctl is-enabled httpd 2>/dev/null | grep -q "enabled" && services+=("httpd")
    systemctl is-enabled caddy 2>/dev/null | grep -q "enabled" && services+=("caddy")
    
    # Databases
    systemctl is-enabled mysql 2>/dev/null | grep -q "enabled" && services+=("mysql")
    systemctl is-enabled mariadb 2>/dev/null | grep -q "enabled" && services+=("mariadb")
    systemctl is-enabled postgresql 2>/dev/null | grep -q "enabled" && services+=("postgresql")
    systemctl is-enabled mongod 2>/dev/null | grep -q "enabled" && services+=("mongod")
    systemctl is-enabled redis-server 2>/dev/null | grep -q "enabled" && services+=("redis-server")
    systemctl is-enabled redis 2>/dev/null | grep -q "enabled" && services+=("redis")
    
    # Containers
    systemctl is-enabled docker 2>/dev/null | grep -q "enabled" && services+=("docker")
    
    # Security
    systemctl is-enabled auditd 2>/dev/null | grep -q "enabled" && services+=("auditd")
    systemctl is-enabled fail2ban 2>/dev/null | grep -q "enabled" && services+=("fail2ban")
    
    # SSH
    systemctl is-enabled sshd 2>/dev/null | grep -q "enabled" && services+=("sshd")
    systemctl is-enabled ssh 2>/dev/null | grep -q "enabled" && services+=("ssh")
    
    echo "${services[@]:-}"
}

#-------------------------------------------------------------------------------
# Get friendly service description
#-------------------------------------------------------------------------------
get_service_description() {
    local svc="$1"
    case "$svc" in
        nginx|apache2|httpd|caddy) echo "🌐 Web Server" ;;
        mysql|mariadb|postgresql|mongod) echo "🗄️ Database" ;;
        redis|redis-server) echo "⚡ Cache Server" ;;
        docker) echo "🐳 Docker" ;;
        auditd|fail2ban) echo "🔒 Security Service" ;;
        sshd|ssh) echo "🔑 SSH Server" ;;
        *) echo "⚙️ Service" ;;
    esac
}

#-------------------------------------------------------------------------------
# Get severity based on service type
#-------------------------------------------------------------------------------
get_service_severity() {
    local svc="$1"
    case "$svc" in
        nginx|apache2|httpd|caddy) echo "critical" ;;
        mysql|mariadb|postgresql|mongod) echo "critical" ;;
        docker) echo "critical" ;;
        sshd|ssh) echo "critical" ;;
        auditd|fail2ban) echo "high" ;;
        redis|redis-server) echo "high" ;;
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
**Action:** Attempting automatic restart..."
        
        "$ALERT_SCRIPT" "watchdog" "Monitor Down" "$MSG" "critical"
        
        systemctl restart "$svc" 2>/dev/null || true
        sleep 2
        
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            "$ALERT_SCRIPT" "watchdog" "Monitor Recovered" "✅ \`${svc}\` restarted successfully" "low"
        fi
    fi
done

#-------------------------------------------------------------------------------
# Check auto-detected important services
#-------------------------------------------------------------------------------
IMPORTANT_SERVICES=$(detect_important_services)

for svc in $IMPORTANT_SERVICES; do
    STATE_FILE="${STATE_DIR}/svc_${svc}"
    WAS_RUNNING="1"
    [[ -f "$STATE_FILE" ]] && WAS_RUNNING=$(cat "$STATE_FILE")
    
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        IS_RUNNING="1"
        
        # Service recovered
        if [[ "$WAS_RUNNING" == "0" ]]; then
            DESC=$(get_service_description "$svc")
            "$ALERT_SCRIPT" "watchdog" "✅ Service Recovered" "${DESC} \`${svc}\` is back online!" "low"
        fi
    else
        IS_RUNNING="0"
        
        # Service down - only alert if it was running before
        if [[ "$WAS_RUNNING" == "1" ]]; then
            DESC=$(get_service_description "$svc")
            SEVERITY=$(get_service_severity "$svc")
            
            MSG="${DESC} has stopped!

**Service:** \`${svc}\`
**Status:** ❌ Not running

_Run:_ \`sudo systemctl status ${svc}\`"
            
            "$ALERT_SCRIPT" "watchdog" "🚨 ${svc} DOWN" "$MSG" "$SEVERITY"
        fi
    fi
    
    echo "$IS_RUNNING" > "$STATE_FILE"
done

#-------------------------------------------------------------------------------
# Check file monitor timer
#-------------------------------------------------------------------------------
if ! systemctl is-active --quiet server-file-monitor.timer 2>/dev/null; then
    "$ALERT_SCRIPT" "watchdog" "Timer Stopped" "File integrity monitor timer stopped" "high"
    systemctl restart server-file-monitor.timer 2>/dev/null || true
fi

#-------------------------------------------------------------------------------
# Check audit rules
#-------------------------------------------------------------------------------
RULE_COUNT=$(auditctl -l 2>/dev/null | wc -l || echo "0")

if [[ $RULE_COUNT -lt 5 ]]; then
    MSG="⚠️ Audit rules may have been tampered!

**Found:** ${RULE_COUNT} rules (expected 5+)"
    
    "$ALERT_SCRIPT" "watchdog" "Audit Rules Modified" "$MSG" "critical"
    
    if [[ -f /etc/audit/rules.d/server-monitor.rules ]]; then
        augenrules --load 2>/dev/null || true
    fi
fi

#-------------------------------------------------------------------------------
# Check critical scripts exist
#-------------------------------------------------------------------------------
for script in alert.sh process-monitor.sh ssh-monitor.sh watchdog.sh; do
    if [[ ! -f "${INSTALL_DIR}/bin/${script}" ]]; then
        "$ALERT_SCRIPT" "watchdog" "Script Deleted" "🚨 \`${script}\` was deleted!" "critical"
    fi
done

#-------------------------------------------------------------------------------
# Check disk space
#-------------------------------------------------------------------------------
DISK_USAGE=$(df "${INSTALL_DIR}" 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%' || echo "0")
if [[ -n "$DISK_USAGE" ]] && [[ $DISK_USAGE -gt 90 ]]; then
    "$ALERT_SCRIPT" "watchdog" "Disk Critical" "💾 Disk usage at ${DISK_USAGE}%!" "high"
fi
