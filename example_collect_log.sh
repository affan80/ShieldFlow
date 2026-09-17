#!/bin/bash

LINUX_USER="socs2"
LINUX_HOST="10.7.19.75"
REMOTE_LOG="/var/log/nginx/access.log"

LOCAL_DIR="./logs"
mkdir -p "$LOCAL_DIR"

LOCAL_FILE="$LOCAL_DIR/access_$(date '+%Y%m%d_%H%M%S').log"

echo "======================================"
echo " Live Access Log Collector"
echo "======================================"
echo "Server : $LINUX_USER@$LINUX_HOST"
echo "Remote : $REMOTE_LOG"
echo "Local  : $LOCAL_FILE"
echo "======================================"
echo ""
echo "Collecting live logs..."
echo "Press Ctrl+C to stop."
echo ""

ssh "$LINUX_USER@$LINUX_HOST" \
    "tail -F '$REMOTE_LOG'" \
    | tee -a "$LOCAL_FILE"
