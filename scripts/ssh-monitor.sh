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
    TIMESTAMP=$(echo "$line" | awk '{print $1" "$2" "$3}')
    USER=$(echo "$line" | grep -oP 'for \K\w+' || echo "unknown")
    IP=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "unknown")
    METHOD=$(echo "$line" | grep -oP 'Accepted \K\w+' || echo "unknown")
    
    MSG="SSH Login Detected:\n"
    MSG+="• **User:** ${USER}\n"
    MSG+="• **From:** ${IP}\n"
    MSG+="• **Method:** ${METHOD}\n"
    MSG+="• **Time:** ${TIMESTAMP}"
    
    # Root login is higher severity
    if [[ "$USER" == "root" ]]; then
        "$ALERT_SCRIPT" "ssh" "Root SSH Login" "$MSG" "high"
    else
        "$ALERT_SCRIPT" "ssh" "SSH Login" "$MSG" "medium"
    fi
done

#-------------------------------------------------------------------------------
# Check for brute force attacks (multiple failed attempts)
#-------------------------------------------------------------------------------
FAILED_COUNT=$(echo "$NEW_ENTRIES" | grep -c "Failed password" || echo "0")

if [[ $FAILED_COUNT -gt 5 ]]; then
    # Get attacking IPs
    ATTACKERS=$(echo "$NEW_ENTRIES" | grep "Failed password" | \
        grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -rn | head -5)
    
    MSG="SSH Brute Force Attack:\n"
    MSG+="• **Failed attempts:** ${FAILED_COUNT}\n"
    MSG+="• **Top attackers:**\n\`\`\`\n${ATTACKERS}\n\`\`\`"
    
    if [[ $FAILED_COUNT -gt 20 ]]; then
        "$ALERT_SCRIPT" "ssh" "Brute Force Attack" "$MSG" "critical"
    else
        "$ALERT_SCRIPT" "ssh" "Brute Force Attack" "$MSG" "high"
    fi
fi

#-------------------------------------------------------------------------------
# Check for invalid users
#-------------------------------------------------------------------------------
INVALID_USERS=$(echo "$NEW_ENTRIES" | grep "Invalid user" | head -5)
if [[ -n "$INVALID_USERS" ]]; then
    COUNT=$(echo "$NEW_ENTRIES" | grep -c "Invalid user" || echo "0")
    
    MSG="SSH Invalid User Attempts:\n"
    MSG+="• **Count:** ${COUNT}\n"
    MSG+="• **Sample attempts:**\n\`\`\`\n${INVALID_USERS}\n\`\`\`"
    
    "$ALERT_SCRIPT" "ssh" "Invalid User Attempts" "$MSG" "medium"
fi

#-------------------------------------------------------------------------------
# Check for privilege escalation (sudo usage)
#-------------------------------------------------------------------------------
echo "$NEW_ENTRIES" | grep -E "sudo:.*COMMAND=" | while read -r line; do
    USER=$(echo "$line" | grep -oP 'sudo:\s+\K\w+' || echo "unknown")
    COMMAND=$(echo "$line" | grep -oP 'COMMAND=\K.*' || echo "unknown")
    
    # Truncate long commands
    COMMAND_SHORT="${COMMAND:0:100}"
    [[ ${#COMMAND} -gt 100 ]] && COMMAND_SHORT+="..."
    
    MSG="Sudo Command Executed:\n"
    MSG+="• **User:** ${USER}\n"
    MSG+="• **Command:** \`${COMMAND_SHORT}\`"
    
    # Critical if sensitive commands
    if echo "$COMMAND" | grep -qE "passwd|shadow|sudoers|visudo|chmod.*777|chown.*root"; then
        "$ALERT_SCRIPT" "privesc" "Sensitive Sudo Command" "$MSG" "high"
    fi
done

#-------------------------------------------------------------------------------
# Check for su usage
#-------------------------------------------------------------------------------
echo "$NEW_ENTRIES" | grep "su\[" | grep "session opened" | while read -r line; do
    FROM_USER=$(echo "$line" | grep -oP 'by \K\w+' || echo "unknown")
    TO_USER=$(echo "$line" | grep -oP 'for user \K\w+' || echo "unknown")
    
    MSG="User Switch (su):\n"
    MSG+="• **From:** ${FROM_USER}\n"
    MSG+="• **To:** ${TO_USER}"
    
    if [[ "$TO_USER" == "root" ]]; then
        "$ALERT_SCRIPT" "privesc" "Switch to Root" "$MSG" "high"
    fi
done

#-------------------------------------------------------------------------------
# Update state
#-------------------------------------------------------------------------------
echo "$CURRENT_LINE" > "$STATE_FILE"
