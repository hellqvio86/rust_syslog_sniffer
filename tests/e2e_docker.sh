#!/bin/bash
set -e

# Build the docker image
echo "Building Docker image..."
make docker-build

# Define variables
INTERFACE="lo"
PORT=5514
IMAGE_NAME="rust-syslog-sniffer:latest"

# Start the sniffer in the background using Docker
# We use --network host to sniff on the host interface 'lo'
# We use --cap-add=NET_RAW and --cap-add=NET_ADMIN for packet capture permissions
# We use --user root to ensure we have permission to open raw sockets (since the image defaults to non-root 'sniffer')
echo "Starting sniffer container with 2s interval..."

# Note: We use 'docker run' directly instead of 'make docker-run' to avoid TTY (-it) issues in background
docker run --rm \
    --network host \
    --cap-add=NET_RAW \
    --cap-add=NET_ADMIN \
    --user root \
    $IMAGE_NAME \
    --interface $INTERFACE --port $PORT --interval 2 > sniffer_output_docker.txt 2>&1 &
SNIFFER_PID=$!

# Start dummy listener on host
nc -u -l -p $PORT > /dev/null &
LISTENER_PID=$!

# Give it a moment to start
sleep 2

# Send a syslog message via UDP
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
echo "Generated Timestamp: $TIMESTAMP"
MESSAGE="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\" eventID=\"1011\"] BOMAn application log entry..."
echo "Sending message: $MESSAGE"
echo -n "$MESSAGE" | nc -u -w 1 127.0.0.1 $PORT

# Wait for sniffer to finish (it should exit after 2s)
echo "Waiting for sniffer to finish..."
wait $SNIFFER_PID || true

# Kill listener
kill $LISTENER_PID || true

# Check output
echo "Checking output..."
cat sniffer_output_docker.txt

# Check for JSON structure and ABSENCE of logs
if grep -q "\"interval_seconds\": 2" sniffer_output_docker.txt && grep -q "\"mymachine.example.com\"" sniffer_output_docker.txt; then
    echo "SUCCESS: JSON Summary found and message captured!"
    
    # Check if logs are present (should NOT be present)
    if grep -q "INFO" sniffer_output_docker.txt; then
        echo "FAILURE: INFO logs found in JSON output (should be quiet)."
        exit 1
    else
        echo "SUCCESS: Output is quiet."
    fi
else
    echo "FAILURE: JSON Summary or message not found in output."
    exit 1
fi
