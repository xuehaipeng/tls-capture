#!/bin/bash

echo "Testing port filtering functionality..."

# Clean up any existing processes
sudo pkill -f tls_capture 2>/dev/null || true
sleep 1

# Detach any existing XDP programs
sudo bpftool net detach xdp dev enp0s1 2>/dev/null || true
sleep 1

echo "Starting TLS capture on port 8443..."
sudo timeout 15s ./tls_capture -i enp0s1 -P 8443 > /tmp/port_test.log 2>&1 &
CAPTURE_PID=$!

echo "Waiting for capture to start..."
sleep 3

echo "Generating traffic on port 443 (should be filtered out)..."
curl -k https://httpbin.org:443/get --max-time 5 > /tmp/curl_443.txt 2>&1 &

echo "Generating traffic on port 8443 (should be captured)..."
curl -k https://httpbin.org:8443/get --max-time 5 > /tmp/curl_8443.txt 2>&1 &

echo "Waiting for traffic generation..."
sleep 8

echo "Stopping capture..."
sudo pkill -f tls_capture 2>/dev/null || true
sleep 2

echo ""
echo "=== Test Results ==="
echo "Log file size: $(wc -l < /tmp/port_test.log) lines"
echo ""
echo "Packets captured from port 443:"
grep -c "443" /tmp/port_test.log || echo "0"
echo ""
echo "Packets captured from port 8443:"
grep -c "8443" /tmp/port_test.log || echo "0"
echo ""
echo "=== BPF Debug Messages ==="
grep "BPF:" /tmp/port_test.log | tail -10

# Clean up
rm -f /tmp/port_test.log /tmp/curl_443.txt /tmp/curl_8443.txt
