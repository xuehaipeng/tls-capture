#!/bin/bash

# Test script for TLS capture tool

# Start the capture tool in the background
echo "Starting TLS capture tool..."
sudo ./tls_capture -i enp0s1 > capture_output.log 2>&1 &

# Save the PID of the capture tool
CAPTURE_PID=$!

# Wait a moment for the capture tool to start
sleep 2

# Generate some TLS traffic
echo "Generating TLS traffic..."
curl -k https://httpbin.org/get > /dev/null 2>&1 &

# Wait for the traffic to be generated
sleep 3

# Kill the capture tool
echo "Stopping TLS capture tool..."
sudo kill $CAPTURE_PID

# Wait for the capture tool to finish
wait $CAPTURE_PID

# Display the captured output
echo "Captured output:"
cat capture_output.log
