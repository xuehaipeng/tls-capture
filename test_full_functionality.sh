#!/bin/bash

echo "Testing full functionality of TLS Capture Tool..."

# Clean up any existing processes
sudo pkill -f tls_capture 2>/dev/null || true
sleep 1

# Detach any existing XDP programs
sudo bpftool net detach xdp dev enp0s1 2>/dev/null || true
sleep 1

# Use the default SSLKEYLOGFILE path that the tool will create
export SSLKEYLOGFILE=/tmp/sslkeylog.txt
rm -f $SSLKEYLOGFILE

echo "Starting TLS capture on port 8443..."
sudo timeout 15s ./tls_capture -i enp0s1 -P 8443 > /tmp/full_test.log 2>&1 &
CAPTURE_PID=$!

echo "Waiting for capture to start..."
sleep 3

echo "Adding SSL keys to SSLKEYLOGFILE..."
echo "CLIENT_RANDOM a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" >> $SSLKEYLOGFILE

echo "Generating HTTPS traffic on port 8443 (should be captured)..."
timeout 5s curl -k https://httpbin.org:8443/get 2>/dev/null || echo "curl failed or timed out (expected)"

echo "Generating HTTPS traffic on port 443 (should be filtered out)..."
timeout 5s curl -k https://httpbin.org:443/get 2>/dev/null || echo "curl failed or timed out (expected)"

echo "Waiting for monitoring..."
sleep 3

echo "Stopping capture..."
sudo pkill -f tls_capture 2>/dev/null || true
sleep 2

echo ""
echo "=== Test Results ==="
echo "Log file size: $(wc -l < /tmp/full_test.log) lines"
echo ""
echo "SSLKEYLOGFILE content:"
cat $SSLKEYLOGFILE
echo ""
echo "Key events from capture log:"
grep -E "(Port filter|SSLKEYLOG|Stored|Loaded|Captured.*8443|Captured.*443)" /tmp/full_test.log || echo "No key events found"
echo ""
echo "Decryption attempts:"
grep -E "(TLS Record|Application Data|Decrypted|Failed to decrypt)" /tmp/full_test.log || echo "No decryption attempts found"

# Clean up
rm -f /tmp/full_test.log $SSLKEYLOGFILE
