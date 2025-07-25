#!/bin/bash

echo "Testing HTTPS traffic capture on port 8443..."

# Clean up any existing processes
sudo pkill -f tls_capture 2>/dev/null || true
sleep 1

# Detach any existing XDP programs
sudo bpftool net detach xdp dev enp0s1 2>/dev/null || true
sleep 1

echo "Starting TLS capture on port 8443..."
sudo timeout 15s ./tls_capture -i enp0s1 -P 8443 > /tmp/https_test.log 2>&1 &
CAPTURE_PID=$!

echo "Waiting for capture to start..."
sleep 3

echo "Generating HTTPS traffic on port 8443..."
# Try to generate some traffic on port 8443
# Note: httpbin.org:8443 might not be accessible, so we'll try a few different approaches

# First, let's try a simple connection to see if we can generate any TLS traffic
timeout 3s openssl s_client -connect httpbin.org:443 -servername httpbin.org 2>/dev/null &
SSL_PID=$!

# Wait a bit for the connection
sleep 2

# Kill the SSL connection
kill $SSL_PID 2>/dev/null || true

echo "Waiting for capture to finish..."
sleep 3

echo "Stopping capture..."
sudo pkill -f tls_capture 2>/dev/null || true
sleep 2

echo ""
echo "=== Test Results ==="
echo "Log file size: $(wc -l < /tmp/https_test.log) lines"
echo ""
echo "Port filter information:"
grep -E "(Port filter|target_port)" /tmp/https_test.log
echo ""
echo "Captured packets:"
grep -E "Captured TLS packet" /tmp/https_test.log || echo "No packets captured"
echo ""
echo "TLS records:"
grep -E "TLS Record" /tmp/https_test.log || echo "No TLS records found"
echo ""
echo "BPF debug output:"
grep -E "BPF:" /tmp/https_test.log | tail -10 || echo "No BPF debug output"

# Clean up
rm -f /tmp/https_test.log
