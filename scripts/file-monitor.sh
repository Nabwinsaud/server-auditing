#!/bin/bash
#===============================================================================
# FILE INTEGRITY MONITOR
# Uses AIDE to detect file changes
#===============================================================================

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/opt/server-monitor/etc/config.env}"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

INSTALL_DIR="${INSTALL_DIR:-/opt/server-monitor}"
ALERT_SCRIPT="${INSTALL_DIR}/bin/alert.sh"
AIDE_DB="/var/lib/aide/aide.db"
AIDE_NEW="/var/lib/aide/aide.db.new"
AIDE_CONF="/etc/aide/aide.conf"

#-------------------------------------------------------------------------------
# Initialize AIDE if needed
#-------------------------------------------------------------------------------
if [[ ! -f "$AIDE_DB" ]]; then
    echo "[INFO] Initializing AIDE database..."
    aide --init -c "$AIDE_CONF" > /dev/null 2>&1 || {
        echo "[ERROR] Failed to initialize AIDE"
        exit 1
    }
    mv "$AIDE_NEW" "$AIDE_DB" 2>/dev/null || true
    echo "[INFO] AIDE database initialized"
    exit 0
fi

#-------------------------------------------------------------------------------
# Run integrity check
#-------------------------------------------------------------------------------
TEMP_OUTPUT=$(mktemp)
aide --check -c "$AIDE_CONF" > "$TEMP_OUTPUT" 2>&1 || true
EXIT_CODE=$?

# Exit codes: 0=no changes, 1-6=changes detected, 7+=error
if [[ $EXIT_CODE -eq 0 ]]; then
    rm -f "$TEMP_OUTPUT"
    exit 0
fi

if [[ $EXIT_CODE -ge 7 ]]; then
    "$ALERT_SCRIPT" "file" "AIDE Error" "AIDE check failed with exit code $EXIT_CODE" "medium"
    rm -f "$TEMP_OUTPUT"
    exit 1
fi

#-------------------------------------------------------------------------------
# Parse changes
#-------------------------------------------------------------------------------
ADDED=$(grep -c "^Added:" "$TEMP_OUTPUT" 2>/dev/null || echo "0")
REMOVED=$(grep -c "^Removed:" "$TEMP_OUTPUT" 2>/dev/null || echo "0")
CHANGED=$(grep -c "^Changed:" "$TEMP_OUTPUT" 2>/dev/null || echo "0")

# Extract specific file changes (limit to 10)
DETAILS=""
if [[ $ADDED -gt 0 ]]; then
    DETAILS+="**Added files:**\n"
    DETAILS+=$(grep "^Added:" "$TEMP_OUTPUT" | head -5 | sed 's/^/• /')
    DETAILS+="\n"
fi

if [[ $REMOVED -gt 0 ]]; then
    DETAILS+="**Removed files:**\n"
    DETAILS+=$(grep "^Removed:" "$TEMP_OUTPUT" | head -5 | sed 's/^/• /')
    DETAILS+="\n"
fi

if [[ $CHANGED -gt 0 ]]; then
    DETAILS+="**Changed files:**\n"
    DETAILS+=$(grep "^Changed:" "$TEMP_OUTPUT" | head -5 | sed 's/^/• /')
    DETAILS+="\n"
fi

#-------------------------------------------------------------------------------
# Determine severity
#-------------------------------------------------------------------------------
SEVERITY="medium"
CRITICAL_PATHS="/etc/passwd|/etc/shadow|/etc/sudoers|/etc/ssh|/usr/bin|/usr/sbin"

if grep -qE "$CRITICAL_PATHS" "$TEMP_OUTPUT"; then
    SEVERITY="critical"
fi

#-------------------------------------------------------------------------------
# Send alert
#-------------------------------------------------------------------------------
MESSAGE="File integrity changes detected:\n"
MESSAGE+="• Added: ${ADDED}\n"
MESSAGE+="• Removed: ${REMOVED}\n"
MESSAGE+="• Changed: ${CHANGED}\n\n"
MESSAGE+="${DETAILS}"
MESSAGE+="\nRun \`aide --check\` for full details"

"$ALERT_SCRIPT" "file" "File Integrity Alert" "$MESSAGE" "$SEVERITY"

rm -f "$TEMP_OUTPUT"
