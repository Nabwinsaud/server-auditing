#!/bin/bash
#===============================================================================
# DISCORD ALERT SENDER
# Rate-limited, formatted alerts to Discord webhook
#===============================================================================

set -euo pipefail

# Load config
CONFIG_FILE="${CONFIG_FILE:-/opt/server-monitor/etc/config.env}"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

# Defaults
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
HOSTNAME="${HOSTNAME:-$(hostname)}"
INSTALL_DIR="${INSTALL_DIR:-/opt/server-monitor}"
RATE_LIMIT_SECONDS="${RATE_LIMIT_SECONDS:-60}"
LOG_FILE="${LOG_FILE:-/opt/server-monitor/logs/monitor.log}"

CACHE_DIR="${INSTALL_DIR}/var/cache"
mkdir -p "$CACHE_DIR"

# Arguments
ALERT_TYPE="${1:-info}"
ALERT_TITLE="${2:-Alert}"
ALERT_MESSAGE="${3:-No message}"
SEVERITY="${4:-medium}"

# Validate webhook
if [[ -z "$DISCORD_WEBHOOK" ]]; then
    echo "[ERROR] DISCORD_WEBHOOK not set" >&2
    exit 1
fi

#-------------------------------------------------------------------------------
# Rate limiting
#-------------------------------------------------------------------------------
CACHE_KEY=$(echo "${ALERT_TITLE}${ALERT_TYPE}" | md5sum | cut -d' ' -f1)
CACHE_FILE="${CACHE_DIR}/alert_${CACHE_KEY}"
NOW=$(date +%s)

if [[ -f "$CACHE_FILE" ]]; then
    LAST_ALERT=$(cat "$CACHE_FILE" 2>/dev/null || echo "0")
    if (( NOW - LAST_ALERT < RATE_LIMIT_SECONDS )); then
        # Rate limited - log locally but don't send
        echo "[$(date)] [RATE_LIMITED] [$SEVERITY] $ALERT_TITLE: $ALERT_MESSAGE" >> "$LOG_FILE"
        exit 0
    fi
fi
echo "$NOW" > "$CACHE_FILE"

#-------------------------------------------------------------------------------
# Color based on severity
#-------------------------------------------------------------------------------
case "$SEVERITY" in
    critical) COLOR=15158332 ;;  # Red
    high)     COLOR=15105570 ;;  # Orange
    medium)   COLOR=16776960 ;;  # Yellow
    low)      COLOR=3066993 ;;   # Green
    info)     COLOR=3447003 ;;   # Blue
    *)        COLOR=9807270 ;;   # Gray
esac

#-------------------------------------------------------------------------------
# Emoji based on type
#-------------------------------------------------------------------------------
case "$ALERT_TYPE" in
    file)     EMOJI="📁" ;;
    process)  EMOJI="⚙️" ;;
    network)  EMOJI="🌐" ;;
    ssh)      EMOJI="🔐" ;;
    privesc)  EMOJI="⚠️" ;;
    watchdog) EMOJI="🐕" ;;
    rootkit)  EMOJI="☠️" ;;
    test)     EMOJI="🧪" ;;
    *)        EMOJI="🚨" ;;
esac

#-------------------------------------------------------------------------------
# Build payload
#-------------------------------------------------------------------------------
# Escape special characters for JSON
escape_json() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    str="${str//$'\t'/  }"
    echo "$str"
}

ESCAPED_MSG=$(escape_json "$ALERT_MESSAGE")
ESCAPED_TITLE=$(escape_json "$ALERT_TITLE")

PAYLOAD=$(cat << EOF
{
    "embeds": [{
        "title": "${EMOJI} ${ESCAPED_TITLE}",
        "description": "${ESCAPED_MSG}",
        "color": ${COLOR},
        "fields": [
            {"name": "🖥️ Host", "value": "${HOSTNAME}", "inline": true},
            {"name": "📊 Severity", "value": "${SEVERITY^^}", "inline": true},
            {"name": "👤 User", "value": "${USER:-system}", "inline": true},
            {"name": "🏷️ Type", "value": "${ALERT_TYPE}", "inline": true}
        ],
        "footer": {"text": "Server Monitor v1.0"},
        "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    }]
}
EOF
)

#-------------------------------------------------------------------------------
# Send to Discord
#-------------------------------------------------------------------------------
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "$DISCORD_WEBHOOK" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" == "204" ]] || [[ "$HTTP_CODE" == "200" ]]; then
    echo "[$(date)] [SENT] [$SEVERITY] $ALERT_TITLE: $ALERT_MESSAGE" >> "$LOG_FILE"
else
    echo "[$(date)] [FAILED:$HTTP_CODE] [$SEVERITY] $ALERT_TITLE: $ALERT_MESSAGE" >> "$LOG_FILE"
fi
