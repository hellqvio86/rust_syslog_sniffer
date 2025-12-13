#!/bin/sh
set -e

# Build the docker image (unless SKIP_DOCKER_BUILD is set)
if [ -z "$SKIP_DOCKER_BUILD" ]; then
  echo "Building Docker image..."
  make docker-build
else
  echo "Skipping Docker build (SKIP_DOCKER_BUILD is set)..."
fi

# Run the sniffer in the background with periodic updates
# We use --network host to be able to sniff on lo (loopback)
# We use --privileged or capabilities to allow packet capture
# We override the user to root to ensure we have permissions to capture on lo
echo "Starting sniffer container with periodic updates (frequency=2s)..."
docker run --rm \
  --name sniffer_periodic_test \
  --network host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --user root \
  syslog_sniffer:latest \
  --interface lo \
  --port 5141 \
  --interval 20 \
  --periodic \
  --frequency 2 > sniffer_output_periodic.txt 2>&1 &

SNIFFER_PID=$!

# Wait for container to be running
echo "Waiting for container to start..."
MAX_RETRIES=10
COUNT=0
while ! docker ps | grep -q sniffer_periodic_test; do
  if [ "$COUNT" -ge "$MAX_RETRIES" ]; then
    echo "Timed out waiting for container to start."
    exit 1
  fi
  sleep 1
  COUNT=$((COUNT+1))
done

# Give application time to initialize socket
sleep 3

# Send first batch of messages
echo "Sending first batch of messages..."
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
MESSAGE1="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\" eventID=\"1011\"] BOMFirst batch message"
echo "$MESSAGE1" | nc -u -w 1 127.0.0.1 5141 > /dev/null 2>&1 || true

# Wait for the first period to pass (frequency is 2s)
sleep 3

# Send second batch of messages
echo "Sending second batch of messages..."
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
MESSAGE2="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\" eventID=\"1011\"] BOMSecond batch message"
echo "$MESSAGE2" | nc -u -w 1 127.0.0.1 5141 > /dev/null 2>&1 || true

# Wait for the sniffer to finish (total interval is 10s)
echo "Waiting for sniffer to finish..."
wait $SNIFFER_PID || true

# Stop the container if it's still running (it should have exited)
docker stop sniffer_periodic_test || true

echo "Checking output..."
cat sniffer_output_periodic.txt

# Verify we have multiple JSON objects
JSON_COUNT=$(grep -c "\"interval_seconds\":" sniffer_output_periodic.txt || true)

if [ "$JSON_COUNT" -ge 2 ]; then
  echo "SUCCESS: Found at least 2 periodic reports."
else
  echo "FAILURE: Expected at least 2 periodic reports, found $JSON_COUNT."
  exit 1
fi

# Verify content of messages
if grep -q "First batch message" sniffer_output_periodic.txt; then
  echo "SUCCESS: First batch message captured."
else
  echo "FAILURE: First batch message NOT found."
  exit 1
fi

if grep -q "Second batch message" sniffer_output_periodic.txt; then
  echo "SUCCESS: Second batch message captured."
else
  echo "FAILURE: Second batch message NOT found."
  exit 1
fi

echo "Periodic E2E test passed!"
rm sniffer_output_periodic.txt
