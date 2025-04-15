#!/bin/bash

# === CONFIGURATION ===
BACKUP_DIR="/etc/reach/mongo_backups"
DATE=$(date +"%Y-%m-%d_%H-%M")
DB_NAME="reach_link"
MONGO_HOST="localhost"
MONGO_PORT="27017"
MONGO_USER="cloudetel"
MONGO_PASS="Cloudetel0108"
AUTH_DB="admin"  # Usually 'admin', can be your DB too
FILENAME="$BACKUP_DIR/mongo_backup_$DATE.gz"

# === CREATE BACKUP DIR ===
mkdir -p "$BACKUP_DIR"

# === BACKUP ===
mongodump --host "$MONGO_HOST" --port "$MONGO_PORT" --db "$DB_NAME" --username "$MONGO_USER" --password "$MONGO_PASS" --authenticationDatabase "$AUTH_DB" --archive="$FILENAME" --gzip

# === DELETE BACKUPS OLDER THAN 7 DAYS ===
find "$BACKUP_DIR" -type f -name "*.gz" -mtime +7 -exec rm {} \;

# === OPTIONAL: UPLOAD TO AWS S3 ===
# aws s3 cp "$FILENAME" s3://your-bucket-name/mongo_backups/
