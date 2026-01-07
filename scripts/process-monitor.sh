#!/bin/bash
#===============================================================================
# PROCESS EXECUTION MONITOR
# Detects suspicious process execution patterns
#===============================================================================

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/opt/server-monitor/etc/config.env}"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

INSTALL_DIR="${INSTALL_DIR:-/opt/server-monitor}"
ALERT_SCRIPT="${INSTALL_DIR}/bin/alert.sh"
STATE_FILE="${INSTALL_DIR}/var/state/processes"
WHITELIST="${INSTALL_DIR}/etc/whitelist.conf"

mkdir -p "$(dirname "$STATE_FILE")"

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------

# Get current process list with details
get_processes() {
    ps -eo pid,ppid,user,comm,args --no-headers 2>/dev/null | \
        awk '{
            pid=$1; ppid=$2; user=$3; comm=$4;
            args="";
            for(i=5;i<=NF;i++) args=args" "$i;
            print pid"|"ppid"|"user"|"comm"|"substr(args,2)
        }'
}

# Check if process matches whitelist
is_whitelisted() {
    local args="$1"
    if [[ ! -f "$WHITELIST" ]]; then
        return 1
    fi
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        [[ "$pattern" =~ ^# ]] && continue
        if echo "$args" | grep -qE "$pattern"; then
            return 0
        fi
    done < "$WHITELIST"
    return 1
}

# Check for suspicious patterns
check_suspicious() {
    local pid="$1"
    local ppid="$2"
    local user="$3"
    local comm="$4"
    local args="$5"
    
    local suspicious=0
    local reasons=()
    local severity="high"
    
    # Pattern 1: nohup/background processes
    if echo "$args" | grep -qiE "nohup\s|&$|\s&\s"; then
        suspicious=1
        reasons+=("Background/nohup execution")
    fi
    
    # Pattern 2: Hidden process names (start with dot)
    if [[ "$comm" =~ ^\. ]]; then
        suspicious=1
        reasons+=("Hidden process name")
        severity="critical"
    fi
    
    # Pattern 3: Known miner process names
    if echo "$comm" | grep -qiE "xmrig|xmr|minerd|kdevtmpfsi|kinsing"; then
        suspicious=1
        reasons+=("Known crypto miner")
        severity="critical"
    fi
    
    # Pattern 4: Reverse shell patterns
    if echo "$args" | grep -qE "bash\s+-i|/dev/tcp/|nc\s+.*-e|python.*pty\.spawn|perl.*socket|php.*fsockopen"; then
        suspicious=1
        reasons+=("Potential reverse shell")
        severity="critical"
    fi
    
    # Pattern 5: Base64 decode execution
    if echo "$args" | grep -qE "base64\s+-d|base64\s+--decode"; then
        suspicious=1
        reasons+=("Base64 decode execution")
    fi
    
    # Pattern 6: Wget/curl to suspicious destinations
    if echo "$args" | grep -qE "(wget|curl).*(pastebin|paste\.ee|ix\.io|transfer\.sh)"; then
        suspicious=1
        reasons+=("Download from paste site")
    fi
    
    # Pattern 7: Memory-only execution
    if echo "$args" | grep -qE "/dev/shm/|/tmp/\.|/var/tmp/\."; then
        suspicious=1
        reasons+=("Execution from volatile/hidden location")
        severity="critical"
    fi
    
    # Pattern 8: Perl/Python one-liners
    if echo "$args" | grep -qE "(perl|python|ruby)\s+-e\s+"; then
        suspicious=1
        reasons+=("Scripting language one-liner")
    fi
    
    if [[ $suspicious -eq 1 ]]; then
        local reason_str=$(IFS=', '; echo "${reasons[*]}")
        echo "${severity}|${reason_str}"
        return 0
    fi
    
    return 1
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

# Initialize state file
[[ ! -f "$STATE_FILE" ]] && get_processes > "$STATE_FILE"

PREVIOUS=$(cat "$STATE_FILE")
CURRENT=$(get_processes)

# Check each process
while IFS='|' read -r pid ppid user comm args; do
    [[ -z "$pid" ]] && continue
    
    # Skip if process existed before
    if echo "$PREVIOUS" | grep -q "^${pid}|"; then
        continue
    fi
    
    # Skip whitelisted
    if is_whitelisted "$args"; then
        continue
    fi
    
    # Check for suspicious patterns
    if result=$(check_suspicious "$pid" "$ppid" "$user" "$comm" "$args"); then
        severity=$(echo "$result" | cut -d'|' -f1)
        reasons=$(echo "$result" | cut -d'|' -f2)
        
        # Truncate long command lines
        args_short="${args:0:200}"
        [[ ${#args} -gt 200 ]] && args_short+="..."
        
        MSG="Suspicious process detected:\n"
        MSG+="• **PID:** ${pid} (Parent: ${ppid})\n"
        MSG+="• **User:** ${user}\n"
        MSG+="• **Command:** ${comm}\n"
        MSG+="• **Reason:** ${reasons}\n"
        MSG+="• **Full command:** \`${args_short}\`"
        
        "$ALERT_SCRIPT" "process" "Suspicious Process" "$MSG" "$severity"
    fi
done <<< "$CURRENT"

# Update state
echo "$CURRENT" > "$STATE_FILE"
