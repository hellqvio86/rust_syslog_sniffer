#!/bin/bash
set -euo pipefail

# Build the docker image (unless SKIP_DOCKER_BUILD is set)
if [ -z "${SKIP_DOCKER_BUILD:-}" ]; then
  echo "Building Docker image..."
  make docker-build
else
  echo "Skipping Docker build (SKIP_DOCKER_BUILD is set)..."
fi

INTERFACE="lo"
PORT=5141
CONTAINER_NAME="sniffer_periodic_test_rust"
OUTPUT_FILE=$(mktemp)

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  if [ -n "${LISTENER_PID:-}" ]; then
    kill "$LISTENER_PID" 2>/dev/null || true
  fi
  rm -f "$OUTPUT_FILE"
}
trap cleanup EXIT

echo "Starting sniffer container with periodic updates (frequency=2s)..."
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

docker run --rm \
  --name "$CONTAINER_NAME" \
  --network host \
  --cap-drop=ALL \
  --cap-add=NET_RAW \
  --user root \
  syslog_sniffer:latest \
  --interface "$INTERFACE" \
  --port "$PORT" \
  --interval 10 \
  --periodic \
  --frequency 2 > "$OUTPUT_FILE" 2>&1 &
SNIFFER_PID=$!

# Start dummy listener on host
nc -u -l -p "$PORT" > /dev/null 2>&1 &
LISTENER_PID=$!

echo "Waiting for container to start..."
MAX_RETRIES=30
COUNT=0
while ! docker ps | grep -q "$CONTAINER_NAME"; do
  if [ "$COUNT" -ge "$MAX_RETRIES" ]; then
    echo "Timed out waiting for container to start."
    exit 1
  fi
  sleep 1
  COUNT=$((COUNT+1))
done

sleep 1

# Send first batch of messages
echo "Sending first batch of messages..."
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
MESSAGE1="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\"] BOMFirst batch message"
for _ in {1..3}; do
  echo "$MESSAGE1" | nc -u -w 1 127.0.0.1 "$PORT" > /dev/null 2>&1 || true
  sleep 0.2
done

# Wait for the first period to pass (frequency is 2s)
sleep 2.5

# Send second batch of messages
echo "Sending second batch of messages..."
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
MESSAGE2="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\"] BOMSecond batch message"
for _ in {1..3}; do
  echo "$MESSAGE2" | nc -u -w 1 127.0.0.1 "$PORT" > /dev/null 2>&1 || true
  sleep 0.2
done

# Wait for second period
sleep 2.5

docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
wait "$SNIFFER_PID" || true

echo "Checking output..."
cat "$OUTPUT_FILE"

JSON_COUNT=$(grep -c "\"interval_seconds\":" "$OUTPUT_FILE" || true)

if [ "$JSON_COUNT" -ge 2 ]; then
  echo "SUCCESS: Found at least 2 periodic reports."
else
  echo "FAILURE: Expected at least 2 periodic reports, found $JSON_COUNT."
  exit 1
fi

if grep -q "First batch message" "$OUTPUT_FILE"; then
  echo "SUCCESS: First batch message captured."
else
  echo "FAILURE: First batch message NOT found."
  exit 1
fi

if grep -q "Second batch message" "$OUTPUT_FILE"; then
  echo "SUCCESS: Second batch message captured."
else
  echo "FAILURE: Second batch message NOT found."
  exit 1
fi

echo "Periodic E2E test passed!"
