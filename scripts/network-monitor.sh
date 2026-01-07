#!/bin/bash
#===============================================================================
# NETWORK CONNECTION MONITOR
# Detects suspicious network connections
#===============================================================================

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/opt/server-monitor/etc/config.env}"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

INSTALL_DIR="${INSTALL_DIR:-/opt/server-monitor}"
ALERT_SCRIPT="${INSTALL_DIR}/bin/alert.sh"
STATE_FILE="${INSTALL_DIR}/var/state/connections"

mkdir -p "$(dirname "$STATE_FILE")"

#-------------------------------------------------------------------------------
# Known suspicious indicators
#-------------------------------------------------------------------------------

# Known bad ports (common backdoor/C2 ports)
BAD_PORTS=(4444 5555 6666 6667 31337 12345 23023 1337 9001 9050 9051)

# Known mining pool ports
MINING_PORTS=(3333 3334 5555 7777 8888 14433 14444 45700)

# Tor ports
TOR_PORTS=(9001 9030 9050 9051 9150)

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------

# Get established connections
get_connections() {
    ss -tupn state established 2>/dev/null | awk 'NR>1 {
        local=$5
        remote=$6
        proc=$7
        gsub(/users:\(\("/, "", proc)
        gsub(/"\).*/, "", proc)
        print local"|"remote"|"proc
    }' | sort -u
}

# Check if port is in array
port_in_array() {
    local port="$1"
    shift
    local arr=("$@")
    for p in "${arr[@]}"; do
        [[ "$port" == "$p" ]] && return 0
    done
    return 1
}

# Extract port from address
get_port() {
    echo "$1" | grep -oE '[0-9]+$'
}

# Extract IP from address
get_ip() {
    echo "$1" | sed 's/:[0-9]*$//'
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

# Initialize state
[[ ! -f "$STATE_FILE" ]] && get_connections > "$STATE_FILE"

PREVIOUS=$(cat "$STATE_FILE")
CURRENT=$(get_connections)

# Check each connection
while IFS='|' read -r local remote process; do
    [[ -z "$remote" ]] && continue
    
    # Skip if connection existed before
    if echo "$PREVIOUS" | grep -qF "$remote"; then
        continue
    fi
    
    remote_port=$(get_port "$remote")
    remote_ip=$(get_ip "$remote")
    local_port=$(get_port "$local")
    
    suspicious=0
    reasons=()
    severity="medium"
    
    # Check 1: Known bad ports
    if port_in_array "$remote_port" "${BAD_PORTS[@]}"; then
        suspicious=1
        reasons+=("Known malicious port ($remote_port)")
        severity="critical"
    fi
    
    # Check 2: Mining pool ports
    if port_in_array "$remote_port" "${MINING_PORTS[@]}"; then
        suspicious=1
        reasons+=("Potential mining pool port ($remote_port)")
        severity="critical"
    fi
    
    # Check 3: Tor ports
    if port_in_array "$remote_port" "${TOR_PORTS[@]}"; then
        suspicious=1
        reasons+=("Tor network port ($remote_port)")
        severity="high"
    fi
    
    # Check 4: IRC ports (common for botnets)
    if [[ "$remote_port" == "6667" ]] || [[ "$remote_port" == "6697" ]]; then
        suspicious=1
        reasons+=("IRC port (potential botnet)")
        severity="high"
    fi
    
    # Check 5: Outbound on ephemeral high ports to non-standard destinations
    # (This could generate false positives - tune as needed)
    if [[ "$remote_port" -gt 50000 ]] && [[ "$remote_port" -lt 65535 ]]; then
        # Only flag if from unexpected process
        if ! echo "$process" | grep -qE "chrome|firefox|node|python|ruby"; then
            suspicious=1
            reasons+=("Unusual high port connection")
            severity="medium"
        fi
    fi
    
    # Send alert if suspicious
    if [[ $suspicious -eq 1 ]]; then
        reason_str=$(IFS=', '; echo "${reasons[*]}")
        
        MSG="Suspicious network connection:\n"
        MSG+="• **Local:** ${local}\n"
        MSG+="• **Remote:** ${remote}\n"
        MSG+="• **Process:** ${process:-unknown}\n"
        MSG+="• **Reason:** ${reason_str}"
        
        "$ALERT_SCRIPT" "network" "Network Anomaly" "$MSG" "$severity"
    fi
done <<< "$CURRENT"

# Update state
echo "$CURRENT" > "$STATE_FILE"
