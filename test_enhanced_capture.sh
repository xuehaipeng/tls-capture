#!/bin/bash

# Test script for enhanced TLS capture tool

echo "=== Testing Enhanced TLS Capture Tool ==="

# Start packet capture in background
echo "Starting packet capture..."
sudo timeout 30s ./tls_capture -i lo > capture_results.log 2>&1 &
CAPTURE_PID=$!

# Wait a moment for capture to start
sleep 2

# Generate HTTPS traffic
echo "Generating HTTPS traffic..."

# Make several requests to external sites
curl -k https://httpbin.org/get > /dev/null 2>&1 &
curl -k https://httpbin.org/user-agent > /dev/null 2>&1 &
curl -k https://httpbin.org/headers > /dev/null 2>&1 &

# Wait for requests to complete
sleep 5

# Kill background curl processes
pkill -f "curl -k https"

# Wait a bit more for capture to pick up packets
sleep 3

# Kill capture process
sudo pkill -f "./tls_capture"

# Wait for capture to finish
wait $CAPTURE_PID 2>/dev/null

echo "Capture completed."

# Display results
echo "=== CAPTURE RESULTS ==="
cat capture_results.log

echo "=== END CAPTURE RESULTS ==="

# Clean up
rm -f capture_results.log

echo "Test completed."
