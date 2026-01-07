#!/bin/bash
#===============================================================================
# ROOTKIT SCANNER
# Runs rkhunter and chkrootkit, sends alerts on findings
#===============================================================================

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/opt/server-monitor/etc/config.env}"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

INSTALL_DIR="${INSTALL_DIR:-/opt/server-monitor}"
ALERT_SCRIPT="${INSTALL_DIR}/bin/alert.sh"
TEMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

#-------------------------------------------------------------------------------
# Run rkhunter
#-------------------------------------------------------------------------------
if command -v rkhunter &> /dev/null; then
    echo "[INFO] Running rkhunter scan..."
    
    # Update database
    rkhunter --update --nocolors > /dev/null 2>&1 || true
    
    # Run check
    rkhunter --check --skip-keypress --nocolors > "${TEMP_DIR}/rkhunter.log" 2>&1 || true
    
    # Check for warnings
    WARNINGS=$(grep -c "Warning:" "${TEMP_DIR}/rkhunter.log" 2>/dev/null || echo "0")
    INFECTED=$(grep -c "Rootkit.*\[ Infected \]" "${TEMP_DIR}/rkhunter.log" 2>/dev/null || echo "0")
    
    if [[ $INFECTED -gt 0 ]]; then
        DETAILS=$(grep "Rootkit.*\[ Infected \]" "${TEMP_DIR}/rkhunter.log" | head -5)
        
        MSG="Rootkit detected by rkhunter:\n"
        MSG+="• **Infected:** ${INFECTED}\n"
        MSG+="• **Details:**\n\`\`\`\n${DETAILS}\n\`\`\`"
        
        "$ALERT_SCRIPT" "rootkit" "ROOTKIT DETECTED" "$MSG" "critical"
    elif [[ $WARNINGS -gt 0 ]]; then
        DETAILS=$(grep "Warning:" "${TEMP_DIR}/rkhunter.log" | head -5)
        
        MSG="rkhunter warnings:\n"
        MSG+="• **Warnings:** ${WARNINGS}\n"
        MSG+="• **Sample:**\n\`\`\`\n${DETAILS}\n\`\`\`"
        
        "$ALERT_SCRIPT" "rootkit" "rkhunter Warnings" "$MSG" "medium"
    fi
fi

#-------------------------------------------------------------------------------
# Run chkrootkit
#-------------------------------------------------------------------------------
if command -v chkrootkit &> /dev/null; then
    echo "[INFO] Running chkrootkit scan..."
    
    chkrootkit > "${TEMP_DIR}/chkrootkit.log" 2>&1 || true
    
    # Check for infections
    INFECTED=$(grep -c "INFECTED" "${TEMP_DIR}/chkrootkit.log" 2>/dev/null || echo "0")
    
    if [[ $INFECTED -gt 0 ]]; then
        DETAILS=$(grep "INFECTED" "${TEMP_DIR}/chkrootkit.log" | head -5)
        
        MSG="Rootkit detected by chkrootkit:\n"
        MSG+="• **Infected items:** ${INFECTED}\n"
        MSG+="• **Details:**\n\`\`\`\n${DETAILS}\n\`\`\`"
        
        "$ALERT_SCRIPT" "rootkit" "ROOTKIT DETECTED" "$MSG" "critical"
    fi
fi

echo "[INFO] Rootkit scan complete"
