#!/bin/bash

echo "Testing SSLKEYLOGFILE monitoring..."

# Clean up any existing processes
sudo pkill -f tls_capture 2>/dev/null || true
sleep 1

# Detach any existing XDP programs
sudo bpftool net detach xdp dev enp0s1 2>/dev/null || true
sleep 1

# Use the default SSLKEYLOGFILE path that the tool will create
export SSLKEYLOGFILE=/tmp/sslkeylog.txt
rm -f $SSLKEYLOGFILE

echo "Starting TLS capture..."
sudo timeout 10s ./tls_capture -i enp0s1 > /tmp/ssl_test.log 2>&1 &
CAPTURE_PID=$!

echo "Waiting for capture to start..."
sleep 3

echo "Adding test entries to SSLKEYLOGFILE..."
echo "CLIENT_RANDOM a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" >> $SSLKEYLOGFILE
echo "CLIENT_RANDOM b1c2d3e4f5a67890b1c2d3e4f5a67890b1c2d3e4f5a67890b1c2d3e4f5a67890 112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00" >> $SSLKEYLOGFILE

echo "Waiting for monitoring..."
sleep 3

echo "Stopping capture..."
sudo pkill -f tls_capture 2>/dev/null || true
sleep 2

echo ""
echo "=== Test Results ==="
echo "Log file size: $(wc -l < /tmp/ssl_test.log) lines"
echo ""
echo "SSLKEYLOGFILE content:"
cat $SSLKEYLOGFILE
echo ""
echo "Capture log:"
grep -E "(SSLKEYLOG|Stored|Loaded)" /tmp/ssl_test.log || echo "No SSL key messages found"

# Clean up
rm -f /tmp/ssl_test.log $SSLKEYLOGFILE
