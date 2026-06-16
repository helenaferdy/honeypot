#!/bin/bash
# Honeypot Storage Housekeeping - Retention: 14 days
# Automatically disabled in simulation mode

CONFIG="/opt/honeypot/config.json"
COWRIE_DB="/opt/honeypot/database/cowrie_history.db"
DIONAEA_DB="/opt/honeypot/database/dionaea_history.db"

MODE=$(python3 -c "import json; print(json.load(open('$CONFIG')).get('mode','live'))" 2>/dev/null)

if [ "$MODE" = "simulation" ]; then
    echo "[$(date)] Housekeeping skipped: config mode is 'simulation'"
    exit 0
fi

cleanup_db() {
    local DB=$1
    local NAME=$2
    if [ ! -f "$DB" ]; then
        echo "[$(date)] $NAME: database not found, skipping"
        return
    fi
    BEFORE=$(stat -c%s "$DB" 2>/dev/null || echo 0)
    sqlite3 "$DB" "DELETE FROM auth WHERE timestamp < datetime('now','-1 day');" 2>/dev/null
    sqlite3 "$DB" "DELETE FROM sessions WHERE starttime < datetime('now','-1 day');" 2>/dev/null
    sqlite3 "$DB" "DELETE FROM input WHERE timestamp < datetime('now','-1 day');" 2>/dev/null
    sqlite3 "$DB" "DELETE FROM downloads WHERE timestamp < datetime('now','-1 day');" 2>/dev/null
    sqlite3 "$DB" "DELETE FROM connections WHERE timestamp < datetime('now','-1 day');" 2>/dev/null
    sqlite3 "$DB" "DELETE FROM malware_captures WHERE timestamp < datetime('now','-1 day');" 2>/dev/null
    sqlite3 "$DB" "PRAGMA auto_vacuum=FULL; VACUUM;" 2>/dev/null
    AFTER=$(stat -c%s "$DB" 2>/dev/null || echo 0)
    echo "[$(date)] $NAME: cleaned. Size: ${BEFORE}b -> ${AFTER}b"
}

cleanup_db "$COWRIE_DB" "cowrie_history"
cleanup_db "$DIONAEA_DB" "dionaea_history"

find /opt/honeypot/dionaea/payloads -type f -mtime +1 -delete 2>/dev/null

echo "[$(date)] Housekeeping complete"
