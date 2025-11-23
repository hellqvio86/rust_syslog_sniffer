#!/bin/bash
set -e

# Build the project
cargo build

# Start the sniffer in the background
# We use sudo because sniffing usually requires it. 
# We sniff on 'lo' (localhost) and a custom port to avoid conflicts.
INTERFACE="lo"
PORT=5514
TARGET="./target/debug/syslog_sniffer"

echo "Starting sniffer on $INTERFACE:$PORT..."
# Use stdbuf to force line buffering so we see output immediately
sudo stdbuf -oL -eL $TARGET --interface $INTERFACE --port $PORT --debug > sniffer_output.txt 2>&1 &
SNIFFER_PID=$!

# Start a dummy UDP listener so nc doesn't get "Connection refused"
# We use a different port or just sink it? 
# Actually, the sniffer is promiscuous (or should be), but on 'lo' it might need a destination.
# We are sending to 127.0.0.1:$PORT. So something needs to listen on $PORT.
# Wait, if we run sniffer on $PORT, does it bind? 
# The sniffer uses pcap, it doesn't bind the socket in a way that consumes packets from the stack's perspective usually.
# So we need a listener.
nc -u -l -p $PORT > /dev/null &
LISTENER_PID=$!

# Give it a moment to start
sleep 2

# Send a syslog message via UDP
# RFC 5424 format with dynamic timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
echo "Generated Timestamp: $TIMESTAMP"
MESSAGE="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\" eventID=\"1011\"] BOMAn application log entry..."
echo "Sending message: $MESSAGE"
echo -n "$MESSAGE" | nc -u -w 1 127.0.0.1 $PORT

# Give it a moment to capture
sleep 2

# Stop the sniffer and listener
echo "Stopping sniffer and listener..."
sudo kill $SNIFFER_PID || true
kill $LISTENER_PID || true

# Check output
echo "Checking output..."
if grep -q "$MESSAGE" sniffer_output.txt; then
    echo "SUCCESS: Message captured!"
    rm sniffer_output.txt
    exit 0
else
    echo "FAILURE: Message not found in output."
    cat sniffer_output.txt
    # rm sniffer_output.txt # Keep it for debugging
    exit 1
fi
