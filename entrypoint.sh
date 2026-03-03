#!/bin/sh
# entrypoint.sh — Fix directory ownership then drop to PUID:PGID
set -e

PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

mkdir -p /app/data/keys /app/data/staging
chown -R "$PUID:$PGID" /app/data

exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups \
    python -u archiver.py "$@"
