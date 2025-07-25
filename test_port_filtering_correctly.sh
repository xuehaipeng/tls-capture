#!/bin/bash

echo "Testing port filtering functionality correctly..."

# Clean up any existing processes
sudo pkill -f tls_capture 2>/dev/null || true
sleep 1

# Detach any existing XDP programs
sudo bpftool net detach xdp dev enp0s1 2>/dev/null || true
sleep 1

echo "Starting TLS capture on port 443..."
sudo timeout 15s ./tls_capture -i enp0s1 -P 443 > /tmp/port_filter_test.log 2>&1 &
CAPTURE_PID=$!

echo "Waiting for capture to start..."
sleep 3

echo "Generating HTTPS traffic on port 443 (should be captured)..."
timeout 3s curl -k https://httpbin.org/get 2>/dev/null || echo "curl completed or timed out"

echo "Generating traffic on port 80 (should be filtered out)..."
timeout 3s curl http://httpbin.org/get 2>/dev/null || echo "curl completed or timed out"

echo "Waiting for capture to finish..."
sleep 3

echo "Stopping capture..."
sudo pkill -f tls_capture 2>/dev/null || true
sleep 2

echo ""
echo "=== Test Results ==="
echo "Log file size: $(wc -l < /tmp/port_filter_test.log) lines"
echo ""
echo "Port filter information:"
grep -E "(Port filter|target_port)" /tmp/port_filter_test.log
echo ""
echo "Captured packets:"
grep -E "Captured TLS packet" /tmp/port_filter_test.log || echo "No packets captured"
echo ""
echo "TLS records:"
grep -E "TLS Record" /tmp/port_filter_test.log || echo "No TLS records found"

# Clean up
rm -f /tmp/port_filter_test.log
