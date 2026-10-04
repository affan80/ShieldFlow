#!/bin/bash

# ============================================================
# Shield Flow v0.5 - Traffic Testing Script
# ============================================================

# Web server IP
TARGET="http://10.7.19.75"

echo "=============================================="
echo "       SHIELD FLOW v0.5 TEST SCRIPT"
echo "=============================================="
echo "Target: $TARGET"
echo

# ------------------------------------------------------------
# Check target
# ------------------------------------------------------------

echo "[1] Checking Nginx..."
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" "$TARGET/"

echo
echo "Press ENTER to start testing..."
read

# ------------------------------------------------------------
# TEST 1 - Normal Traffic
# ------------------------------------------------------------

echo
echo "=============================================="
echo "TEST 1: NORMAL TRAFFIC"
echo "=============================================="

for i in {1..10}
do
    curl -s "$TARGET/" > /dev/null
    echo "Request $i/10"
    sleep 0.5
done

echo "Normal traffic complete."

sleep 2

# ------------------------------------------------------------
# TEST 2 - Moderate Burst
# ------------------------------------------------------------

echo
echo "=============================================="
echo "TEST 2: MODERATE BURST"
echo "=============================================="

for i in {1..50}
do
    curl -s "$TARGET/" > /dev/null &
done

wait

echo "50 burst requests complete."

sleep 3

# ------------------------------------------------------------
# TEST 3 - 404 ERROR TRAFFIC
# ------------------------------------------------------------

echo
echo "=============================================="
echo "TEST 3: 404 ERROR TRAFFIC"
echo "=============================================="

for i in {1..20}
do
    curl -s "$TARGET/does-not-exist-$i" > /dev/null
done

echo "20 invalid requests complete."

sleep 3

# ------------------------------------------------------------
# TEST 4 - MIXED ENDPOINTS
# ------------------------------------------------------------

echo
echo "=============================================="
echo "TEST 4: MIXED ENDPOINT TRAFFIC"
echo "=============================================="

paths=(
    "/"
    "/"
    "/"
    "/favicon.ico"
    "/robots.txt"
    "/api"
    "/api/metrics"
    "/does-not-exist"
)

for i in {1..40}
do
    path=${paths[$((RANDOM % ${#paths[@]}))]}

    status=$(curl -s -o /dev/null \
        -w "%{http_code}" \
        "$TARGET$path")

    echo "GET $path -> $status"
done

echo "Mixed traffic complete."

sleep 3

# ------------------------------------------------------------
# TEST 5 - SUSTAINED TRAFFIC
# ------------------------------------------------------------

echo
echo "=============================================="
echo "TEST 5: SUSTAINED TRAFFIC"
echo "=============================================="

echo "Sending requests for 20 seconds..."

START=$(date +%s)
COUNT=0

while true
do
    NOW=$(date +%s)

    if [ $((NOW - START)) -ge 20 ]
    then
        break
    fi

    curl -s "$TARGET/" > /dev/null &

    COUNT=$((COUNT + 1))

    # Prevent unlimited local processes
    if (( COUNT % 20 == 0 ))
    then
        wait
    fi
done

wait

echo
echo "Sustained traffic complete."
echo "Requests generated: $COUNT"

sleep 3

# ------------------------------------------------------------
# TEST 6 - ERROR BURST
# ------------------------------------------------------------

echo
echo "=============================================="
echo "TEST 6: ERROR BURST"
echo "=============================================="

for i in {1..50}
do
    curl -s "$TARGET/random-invalid-$i" > /dev/null &
done

wait

echo "50 error requests complete."

sleep 3

# ------------------------------------------------------------
# FINAL
# ------------------------------------------------------------

echo
echo "=============================================="
echo "TESTING COMPLETE"
echo "=============================================="

echo
echo "Target server: 10.7.19.75"
echo
echo "Check the Shield Flow dashboard now."
echo
echo "Expected observations:"
echo
echo "  - Requests/sec increases"
echo "  - Requests/min increases"
echo "  - Your testing machine IP appears in Top Talkers"
echo "  - Traffic percentage increases"
echo "  - 4xx count increases"
echo "  - Error rate increases during error tests"
echo "  - Recent requests update"
echo
echo "=============================================="
