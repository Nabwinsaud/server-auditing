#!/bin/bash
#===============================================================================
# DISCORD ALERT SENDER
# Rate-limited, formatted alerts to Discord webhook
# 
# SECURITY: This script only sends outbound HTTPS requests to Discord.
# Webhook URL should be kept confidential in config.env (chmod 600)
#===============================================================================

set -euo pipefail

# Load config
CONFIG_FILE="${CONFIG_FILE:-/opt/server-monitor/etc/config.env}"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

# Defaults
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
HOSTNAME="${HOSTNAME:-$(hostname)}"
INSTALL_DIR="${INSTALL_DIR:-/opt/server-monitor}"
RATE_LIMIT_SECONDS="${RATE_LIMIT_SECONDS:-300}"  # 5 minutes default to prevent spam
LOG_FILE="${LOG_FILE:-/opt/server-monitor/logs/monitor.log}"

CACHE_DIR="${INSTALL_DIR}/var/cache"
DEDUP_DIR="${INSTALL_DIR}/var/dedup"
mkdir -p "$CACHE_DIR" "$DEDUP_DIR"

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
# Deduplication - Don't send exact same alert content twice
#-------------------------------------------------------------------------------
CONTENT_HASH=$(echo "${ALERT_TITLE}|${ALERT_MESSAGE}" | md5sum | cut -d' ' -f1)
DEDUP_FILE="${DEDUP_DIR}/${CONTENT_HASH}"

if [[ -f "$DEDUP_FILE" ]]; then
    # Already sent this exact alert, skip
    exit 0
fi
# Mark as sent (cleanup old dedup files older than 1 hour)
find "$DEDUP_DIR" -type f -mmin +60 -delete 2>/dev/null || true
touch "$DEDUP_FILE"

#-------------------------------------------------------------------------------
# Rate limiting by alert type (prevents flood of similar alerts)
#-------------------------------------------------------------------------------
CACHE_KEY=$(echo "${ALERT_TITLE}${ALERT_TYPE}" | md5sum | cut -d' ' -f1)
CACHE_FILE="${CACHE_DIR}/alert_${CACHE_KEY}"
NOW=$(date +%s)

if [[ -f "$CACHE_FILE" ]]; then
    LAST_ALERT=$(cat "$CACHE_FILE" 2>/dev/null || echo "0")
    if (( NOW - LAST_ALERT < RATE_LIMIT_SECONDS )); then
        echo "[$(date)] [RATE_LIMITED] [$SEVERITY] $ALERT_TITLE" >> "$LOG_FILE"
        exit 0
    fi
fi
echo "$NOW" > "$CACHE_FILE"

#-------------------------------------------------------------------------------
# Severity styling - User-friendly colors and labels
#-------------------------------------------------------------------------------
case "$SEVERITY" in
    critical) 
        COLOR=15158332   # Red
        SEV_EMOJI="🔴"
        SEV_LABEL="CRITICAL"
        ;;
    high)     
        COLOR=15105570   # Orange
        SEV_EMOJI="🟠"
        SEV_LABEL="HIGH"
        ;;
    medium)   
        COLOR=16776960   # Yellow
        SEV_EMOJI="🟡"
        SEV_LABEL="MEDIUM"
        ;;
    low)      
        COLOR=3066993    # Green
        SEV_EMOJI="🟢"
        SEV_LABEL="LOW"
        ;;
    info)     
        COLOR=3447003    # Blue
        SEV_EMOJI="🔵"
        SEV_LABEL="INFO"
        ;;
    *)        
        COLOR=9807270    # Gray
        SEV_EMOJI="⚪"
        SEV_LABEL="UNKNOWN"
        ;;
esac

#-------------------------------------------------------------------------------
# Type emoji and friendly labels
#-------------------------------------------------------------------------------
case "$ALERT_TYPE" in
    file)     EMOJI="📁"; TYPE_LABEL="File Change" ;;
    process)  EMOJI="⚙️"; TYPE_LABEL="Process Alert" ;;
    network)  EMOJI="🌐"; TYPE_LABEL="Network Activity" ;;
    ssh)      EMOJI="🔐"; TYPE_LABEL="SSH Activity" ;;
    privesc)  EMOJI="⚠️"; TYPE_LABEL="Privilege Change" ;;
    watchdog) EMOJI="🐕"; TYPE_LABEL="System Health" ;;
    rootkit)  EMOJI="☠️"; TYPE_LABEL="Security Scan" ;;
    test)     EMOJI="✅"; TYPE_LABEL="Test" ;;
    *)        EMOJI="🚨"; TYPE_LABEL="Alert" ;;
esac

#-------------------------------------------------------------------------------
# Format message - Convert \n to actual newlines for Discord
#-------------------------------------------------------------------------------
# Replace literal \n with actual newlines, then format for JSON
format_message() {
    local msg="$1"
    # Replace literal \n with actual newline
    msg="${msg//\\n/$'\n'}"
    # Remove ** markdown for cleaner look (Discord handles it)
    echo "$msg"
}

FORMATTED_MSG=$(format_message "$ALERT_MESSAGE")

#-------------------------------------------------------------------------------
# Build payload with improved UI using jq for proper JSON escaping
#-------------------------------------------------------------------------------
PAYLOAD=$(jq -n \
    --arg title "${EMOJI} ${ALERT_TITLE}" \
    --arg desc "$FORMATTED_MSG" \
    --arg host "$HOSTNAME" \
    --arg sev "${SEV_EMOJI} ${SEV_LABEL}" \
    --arg type "${TYPE_LABEL}" \
    --arg time "$(date '+%b %d, %Y at %I:%M %p')" \
    --argjson color "$COLOR" \
    '{
        embeds: [{
            title: $title,
            description: $desc,
            color: $color,
            fields: [
                {name: "🖥️ Server", value: ("**" + $host + "**"), inline: true},
                {name: "📊 Severity", value: $sev, inline: true},
                {name: "🏷️ Category", value: $type, inline: true}
            ],
            footer: {text: ("🛡️ Server Monitor • " + $time)}
        }]
    }'
)

#-------------------------------------------------------------------------------
# Send to Discord
#-------------------------------------------------------------------------------
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "$DISCORD_WEBHOOK" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" == "204" ]] || [[ "$HTTP_CODE" == "200" ]]; then
    echo "[$(date)] [SENT] [$SEVERITY] $ALERT_TITLE" >> "$LOG_FILE"
else
    echo "[$(date)] [FAILED:$HTTP_CODE] [$SEVERITY] $ALERT_TITLE" >> "$LOG_FILE"
    # Remove dedup file so it can retry
    rm -f "$DEDUP_FILE" 2>/dev/null || true
fi
