#!/bin/bash
set -e

# Build the project
cargo build

# Start the sniffer in the background
# We use sudo because sniffing usually requires it. 
# We sniff on 'lo' (localhost) and a custom port to avoid conflicts.
# Refresh sudo credentials to avoid password prompt in background
if ! sudo -v; then
    echo "Failed to update sudo timestamp. Please run 'sudo -v' manually or enter password."
    exit 1
fi

# Verify we have sudo access without password now
if ! sudo -n true; then
    echo "Sudo still requires password. Aborting."
    exit 1
fi

# Fail fast if user doesn't enter password (don't wait 1 minute)
if ! sudo -n true 2>/dev/null; then
    echo "Sudo password required. You have 15 seconds to enter it."
    if ! timeout 15 sudo -v; then
        echo "Sudo password entry timed out or failed."
        exit 1
    fi
fi

INTERFACE="lo"
PORT=5514
TARGET="./target/debug/syslog_sniffer"

# Run sniffer for 2 seconds and check summary in JSON
# We expect NO logs to stderr/stdout by default (unless RUST_LOG is set or --debug)
echo "Starting sniffer with 2s interval..."

sudo stdbuf -oL -eL $TARGET --interface $INTERFACE --port $PORT --interval 2 > sniffer_output.txt 2>&1 &
SNIFFER_PID=$!

# Start dummy listener
nc -u -l -p $PORT > /dev/null &
LISTENER_PID=$!

# Give it a moment to start
sleep 1

# Send a syslog message via UDP
# RFC 5424 format with dynamic timestamp
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
cat sniffer_output.txt

# Check for JSON structure and ABSENCE of logs
# Note: interval_seconds should be 2 now
if grep -q "\"interval_seconds\": 2" sniffer_output.txt && grep -q "\"mymachine.example.com\"" sniffer_output.txt; then
    echo "SUCCESS: JSON Summary found and message captured!"
    
    # Check if logs are present (should NOT be present)
    if grep -q "INFO" sniffer_output.txt; then
        echo "FAILURE: INFO logs found in JSON output (should be quiet)."
        exit 1
    else
        echo "SUCCESS: Output is quiet."
    fi
else
    echo "FAILURE: JSON Summary or message not found in output."
    # rm sniffer_output.txt # Keep it for debugging
    exit 1
fi
