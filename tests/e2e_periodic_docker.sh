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
TMP_DIR=$(mktemp -d)

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  if [ -n "${LISTENER_PID:-}" ]; then
    kill "$LISTENER_PID" 2>/dev/null || true
  fi
  rm -f "$OUTPUT_FILE"
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# 1. Test missing interface -> non-zero exit code
echo "Testing missing interface fails fast with non-zero exit..."
set +e
docker run --rm \
  --network host \
  --cap-drop=ALL \
  --cap-add=NET_RAW \
  --user root \
  syslog_sniffer:latest \
  --interface "non_existent_dev_xyz" \
  --port "$PORT" > /dev/null 2>&1
MISSING_IF_STATUS=$?
set -e
if [ "$MISSING_IF_STATUS" -eq 0 ]; then
  echo "FAILURE: Expected non-zero exit for missing interface, got 0"
  exit 1
fi
echo "SUCCESS: Missing interface exited with non-zero code ($MISSING_IF_STATUS)."

# 2. Test live capture with periodic reporting, IPv6, non-UTF-8, multibyte P0-1, and SIGTERM clean exit
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
  --periodic \
  --frequency 2 \
  --debug > "$OUTPUT_FILE" 2>&1 &
SNIFFER_PID=$!

# Start dummy listener on host to prevent ICMP port unreachable
nc -u -l -p "$PORT" > /dev/null 2>&1 &
LISTENER_PID=$!

echo "Waiting for sniffer to initialize..."
MAX_RETRIES=40
COUNT=0
while ! grep -q "Starting capture loop" "$OUTPUT_FILE"; do
  if [ "$COUNT" -ge "$MAX_RETRIES" ]; then
    echo "Timed out waiting for sniffer container to start."
    cat "$OUTPUT_FILE"
    exit 1
  fi
  sleep 0.2
  COUNT=$((COUNT+1))
done

echo "Sending first batch of messages (including IPv6, non-UTF8, multibyte P0-1)..."
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
MESSAGE1="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\"] BOMFirst batch message"
for _ in {1..3}; do
  echo "$MESSAGE1" | nc -u -w 1 127.0.0.1 "$PORT" > /dev/null 2>&1 || true
  sleep 0.1
done

# IPv6 ::1 test
python3 -c "import socket; s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.sendto(b'<13>Oct 11 22:14:15 ipv6host test ipv6 payload\n', ('::1', $PORT))" || true

# Non-UTF8 payload test
python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'<13>Oct 11 22:14:15 nonutf8host bad \xff\xfe bytes\n', ('127.0.0.1', $PORT))" || true

# Multibyte after PRI (P0-1) test
python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'<13>\xc3\x96\xf0\x9f\x98\x80xxxxxxxxxxxxx\n', ('127.0.0.1', $PORT))" || true

# Wait for the first period to pass (frequency is 2s)
sleep 2.5

# Send second batch of messages
echo "Sending second batch of messages..."
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
MESSAGE2="<165>1 $TIMESTAMP mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut=\"3\"] BOMSecond batch message"
for _ in {1..3}; do
  echo "$MESSAGE2" | nc -u -w 1 127.0.0.1 "$PORT" > /dev/null 2>&1 || true
  sleep 0.1
done

# Wait for second period
sleep 2.5

# Stop container via SIGTERM and assert clean exit 0 (without || true!)
echo "Stopping container via SIGTERM..."
docker stop -t 5 "$CONTAINER_NAME" >/dev/null
wait "$SNIFFER_PID"

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

if grep -q "ipv6host" "$OUTPUT_FILE"; then
  echo "SUCCESS: IPv6 host captured."
else
  echo "FAILURE: IPv6 host NOT found."
  exit 1
fi

if grep -q "nonutf8host" "$OUTPUT_FILE"; then
  echo "SUCCESS: non-UTF-8 host captured."
else
  echo "FAILURE: non-UTF-8 host NOT found."
  exit 1
fi

# 3. Pcap replay with decoy port (P0-2) in Docker
echo "Testing PCAP replay with decoy port in Docker..."
PCAP_PATH="$TMP_DIR/decoy_test.pcap"
python3 -c "
import struct
def craft_pkt(port, payload):
    dst_mac = b'\x00\x11\x22\x33\x44\x55'
    src_mac = b'\x66\x77\x88\x99\xaa\xbb'
    eth = dst_mac + src_mac + b'\x08\x00'
    tot_len = 20 + 8 + len(payload)
    ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot_len, 1, 0, 64, 17, 0, bytes([192, 168, 1, 10]), bytes([192, 168, 1, 1]))
    udp_hdr = struct.pack('!HHHH', 12345, port, 8 + len(payload), 0)
    return eth + ip_hdr + udp_hdr + payload

p1 = craft_pkt(514, b'<13>Oct 11 22:14:15 pcapmatch test message\n')
p2 = craft_pkt(9999, b'<13>Oct 11 22:14:15 pcapdecoy decoy message\n')

hdr = struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) # Ethernet
with open('$PCAP_PATH', 'wb') as f:
    f.write(hdr)
    for p in [p1, p2]:
        f.write(struct.pack('!IIII', 1700000000, 0, len(p), len(p)))
        f.write(p)
"

PCAP_OUTPUT=$(docker run --rm \
  -v "$TMP_DIR:$TMP_DIR:ro" \
  syslog_sniffer:latest \
  --read-pcap "$PCAP_PATH" \
  --port 514)

echo "PCAP output:"
echo "$PCAP_OUTPUT"

if echo "$PCAP_OUTPUT" | grep -q "pcapmatch" && ! echo "$PCAP_OUTPUT" | grep -q "pcapdecoy"; then
  echo "SUCCESS: PCAP replay filtered decoy port correctly."
else
  echo "FAILURE: PCAP replay did not filter decoy port correctly."
  exit 1
fi

echo "All E2E tests passed successfully!"
