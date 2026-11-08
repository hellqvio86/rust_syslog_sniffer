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
PORT=5514
IMAGE_NAME="syslog_sniffer:latest"
CONTAINER_NAME="sniffer_e2e_test_rust"
OUTPUT_FILE=$(mktemp)

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  if [ -n "${LISTENER_PID:-}" ]; then
    kill "$LISTENER_PID" 2>/dev/null || true
  fi
  rm -f "$OUTPUT_FILE"
}
trap cleanup EXIT

echo "Starting sniffer container..."
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

docker run --rm \
    --name "$CONTAINER_NAME" \
    --network host \
    --cap-drop=ALL \
    --cap-add=NET_RAW \
    --user root \
    "$IMAGE_NAME" \
    --interface "$INTERFACE" --port "$PORT" --interval 3 > "$OUTPUT_FILE" 2>&1 &
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

# Send syslog message via UDP
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
echo "Generated Timestamp: $TIMESTAMP"
MESSAGE="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\"] BOMAn application log entry..."
echo "Sending message: $MESSAGE"

for _ in {1..5}; do
  if ! kill -0 "$SNIFFER_PID" 2>/dev/null; then
    break
  fi
  echo -n "$MESSAGE" | nc -u -w 1 127.0.0.1 "$PORT" >/dev/null 2>&1 || true
  sleep 0.3
done

echo "Waiting for sniffer to finish..."
wait "$SNIFFER_PID"

echo "Checking output..."
cat "$OUTPUT_FILE"

# Check for JSON structure and message
if grep -q "\"interval_seconds\": 3" "$OUTPUT_FILE" && grep -q "\"mymachine.example.com\"" "$OUTPUT_FILE"; then
    echo "SUCCESS: JSON Summary found and message captured!"

    if grep -qE "ERROR|WARN|panicked" "$OUTPUT_FILE"; then
        echo "FAILURE: Error or panic found in output."
        exit 1
    else
        echo "SUCCESS: Output is clean."
    fi
else
    echo "FAILURE: JSON Summary or message not found in output."
    exit 1
fi

echo "E2E Docker test passed!"
