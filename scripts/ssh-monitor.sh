#!/bin/bash
#===============================================================================
# SSH ACTIVITY MONITOR
# Monitors SSH logins, failed attempts, and privilege escalation
#===============================================================================

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/opt/server-monitor/etc/config.env}"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

INSTALL_DIR="${INSTALL_DIR:-/opt/server-monitor}"
ALERT_SCRIPT="${INSTALL_DIR}/bin/alert.sh"
STATE_FILE="${INSTALL_DIR}/var/state/ssh_logins"
AUTH_LOG="/var/log/auth.log"

mkdir -p "$(dirname "$STATE_FILE")"

# Alternative log location for some distros
[[ ! -f "$AUTH_LOG" ]] && AUTH_LOG="/var/log/secure"
[[ ! -f "$AUTH_LOG" ]] && { echo "[WARN] No auth log found"; exit 0; }

#-------------------------------------------------------------------------------
# Get last processed line number
#-------------------------------------------------------------------------------
LAST_LINE=0
[[ -f "$STATE_FILE" ]] && LAST_LINE=$(cat "$STATE_FILE" 2>/dev/null || echo "0")

CURRENT_LINE=$(wc -l < "$AUTH_LOG")

# If log was rotated
if [[ $LAST_LINE -gt $CURRENT_LINE ]]; then
    LAST_LINE=0
fi

# Process new lines
if [[ $CURRENT_LINE -le $LAST_LINE ]]; then
    exit 0
fi

LINES_TO_PROCESS=$((CURRENT_LINE - LAST_LINE))
NEW_ENTRIES=$(tail -n "$LINES_TO_PROCESS" "$AUTH_LOG")

#-------------------------------------------------------------------------------
# Check for successful SSH logins
#-------------------------------------------------------------------------------
echo "$NEW_ENTRIES" | grep "Accepted" | while read -r line; do
    # Parse: Jan  7 10:23:45 hostname sshd[1234]: Accepted publickey for user from 1.2.3.4
    USER=$(echo "$line" | grep -oP 'for \K\w+' || echo "unknown")
    IP=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "unknown")
    METHOD=$(echo "$line" | grep -oP 'Accepted \K\w+' || echo "unknown")
    PORT=$(echo "$line" | grep -oP 'port \K[0-9]+' || echo "unknown")
    
    # Try to get hostname/device name from IP (reverse DNS)
    DEVICE_NAME=$(host "$IP" 2>/dev/null | grep -oP 'pointer \K[^.]+' || echo "")
    
    # Check if local/internal IP
    if [[ "$IP" =~ ^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; then
        IP_TYPE="🏠 Local Network"
    else
        IP_TYPE="🌍 External"
    fi
    
    # Build message with all available info
    MSG="👤 **User:** \`${USER}\`
📍 **IP Address:** \`${IP}\` (${IP_TYPE})"
    
    # Add device name if found
    if [[ -n "$DEVICE_NAME" ]]; then
        MSG+="
💻 **Device:** \`${DEVICE_NAME}\`"
    fi
    
    MSG+="
🔑 **Auth Method:** ${METHOD}
🚪 **Port:** ${PORT}"
    
    # Root login is higher severity
    if [[ "$USER" == "root" ]]; then
        "$ALERT_SCRIPT" "ssh" "⚠️ Root Login Detected" "$MSG" "high"
    else
        "$ALERT_SCRIPT" "ssh" "User Login" "$MSG" "low"
    fi
done

#-------------------------------------------------------------------------------
# Check for brute force attacks (multiple failed attempts)
#-------------------------------------------------------------------------------
FAILED_COUNT=$(echo "$NEW_ENTRIES" | grep -c "Failed password" || echo "0")

if [[ $FAILED_COUNT -gt 5 ]]; then
    # Get attacking IPs
    ATTACKERS=$(echo "$NEW_ENTRIES" | grep "Failed password" | \
        grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -rn | head -3 | \
        awk '{print "• " $2 " (" $1 " attempts)"}')
    
    MSG="🚫 **Failed Attempts:** ${FAILED_COUNT}

**Top Attacking IPs:**
${ATTACKERS}

_Consider blocking these IPs if attacks continue_"
    
    if [[ $FAILED_COUNT -gt 20 ]]; then
        "$ALERT_SCRIPT" "ssh" "🚨 Brute Force Attack!" "$MSG" "critical"
    else
        "$ALERT_SCRIPT" "ssh" "Failed Login Attempts" "$MSG" "high"
    fi
fi

#-------------------------------------------------------------------------------
# Check for invalid users - Show REAL attacker IPs
#-------------------------------------------------------------------------------
INVALID_COUNT=$(echo "$NEW_ENTRIES" | grep -c "Invalid user" || echo "0")

if [[ $INVALID_COUNT -gt 3 ]]; then
    # Get usernames AND IPs of attackers
    INVALID_NAMES=$(echo "$NEW_ENTRIES" | grep "Invalid user" | \
        grep -oP 'Invalid user \K\w+' | sort | uniq | head -5 | \
        tr '\n' ', ' | sed 's/,$//')
    
    # Get attacker IPs with counts
    ATTACKER_IPS=$(echo "$NEW_ENTRIES" | grep "Invalid user" | \
        grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -rn | head -5 | \
        awk '{print "• **" $2 "** (" $1 " attempts)"}')
    
    MSG="🔍 **Total Attempts:** ${INVALID_COUNT}

**Attacker IPs:**
${ATTACKER_IPS}

**Usernames tried:** \`${INVALID_NAMES}\`

_These are real attackers scanning your server_"
    
    "$ALERT_SCRIPT" "ssh" "Invalid Username Attempts" "$MSG" "medium"
fi

#-------------------------------------------------------------------------------
# Check for privilege escalation (sudo usage) - Only alert on sensitive commands
#-------------------------------------------------------------------------------
echo "$NEW_ENTRIES" | grep -E "sudo:.*COMMAND=" | while read -r line; do
    USER=$(echo "$line" | grep -oP 'sudo:\s+\K\w+' || echo "unknown")
    COMMAND=$(echo "$line" | grep -oP 'COMMAND=\K.*' || echo "unknown")
    
    # Only alert on sensitive commands, not routine ones
    if echo "$COMMAND" | grep -qE "passwd|shadow|sudoers|visudo|chmod.*777|chown.*root|rm -rf|useradd|userdel|groupadd"; then
        COMMAND_SHORT="${COMMAND:0:80}"
        [[ ${#COMMAND} -gt 80 ]] && COMMAND_SHORT+="..."
        
        MSG="👤 **User:** \`${USER}\`
💻 **Command:** \`${COMMAND_SHORT}\`

_Sensitive system command executed_"
        
        "$ALERT_SCRIPT" "privesc" "Sensitive Command" "$MSG" "high"
    fi
done

#-------------------------------------------------------------------------------
# Check for su usage (switching to root)
#-------------------------------------------------------------------------------
echo "$NEW_ENTRIES" | grep "su\[" | grep "session opened" | while read -r line; do
    FROM_USER=$(echo "$line" | grep -oP 'by \K\w+' || echo "unknown")
    TO_USER=$(echo "$line" | grep -oP 'for user \K\w+' || echo "unknown")
    
    # Only alert when switching to root
    if [[ "$TO_USER" == "root" ]]; then
        MSG="👤 **From:** \`${FROM_USER}\`
👑 **To:** \`root\`

_User elevated to root privileges_"
        
        "$ALERT_SCRIPT" "privesc" "Root Access" "$MSG" "high"
    fi
done

#-------------------------------------------------------------------------------
# Update state
#-------------------------------------------------------------------------------
echo "$CURRENT_LINE" > "$STATE_FILE"
