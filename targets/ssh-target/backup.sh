#!/bin/bash
# Intentionally world-writable backup script (cron priv-esc challenge)
# A CTF player who can write to this file can escalate to root via cron

BACKUP_DIR="/tmp/backups"
mkdir -p "$BACKUP_DIR"

# Back up sensitive files (intentional misconfiguration)
cp /etc/passwd "$BACKUP_DIR/passwd.bak"
cp /etc/shadow "$BACKUP_DIR/shadow.bak" 2>/dev/null || true

echo "[$(date)] Backup completed" >> /var/log/backup.log
