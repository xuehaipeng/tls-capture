#!/bin/bash

echo "Testing SSLKEYLOGFILE decryption functionality..."

# Clean up any existing processes
sudo pkill -f tls_capture 2>/dev/null || true
sleep 1

# Detach any existing XDP programs
sudo bpftool net detach xdp dev enp0s1 2>/dev/null || true
sleep 1

# Create a temporary SSLKEYLOGFILE with test keys
SSLKEYLOGFILE="/tmp/test_sslkeylog.txt"
rm -f $SSLKEYLOGFILE

echo "Creating test SSLKEYLOGFILE with sample keys..."
cat > $SSLKEYLOGFILE << EOF
# Sample SSL key log entries for testing
CLIENT_RANDOM a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
CLIENT_RANDOM b1c2d3e4f5a67890b1c2d3e4f5a67890b1c2d3e4f5a67890b1c2d3e4f5a67890 112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00
EOF

echo "Setting SSLKEYLOGFILE environment variable..."
export SSLKEYLOGFILE=$SSLKEYLOGFILE

echo "Starting TLS capture with SSLKEYLOGFILE support..."
sudo timeout 10s ./tls_capture -i enp0s1 -P 443 > /tmp/sslkeylog_test.log 2>&1 &
CAPTURE_PID=$!

echo "Waiting for capture to start..."
sleep 3

echo "Generating HTTPS traffic on port 443..."
timeout 3s curl -k https://httpbin.org/get 2>/dev/null || echo "curl completed or timed out"

echo "Waiting for capture to finish..."
sleep 3

echo "Stopping capture..."
sudo pkill -f tls_capture 2>/dev/null || true
sleep 2

echo ""
echo "=== Test Results ==="
echo "Log file size: $(wc -l < /tmp/sslkeylog_test.log) lines"
echo ""
echo "SSLKEYLOGFILE content:"
cat $SSLKEYLOGFILE
echo ""
echo "SSLKEYLOGFILE monitoring messages:"
grep -E "(SSLKEYLOG|Stored|Loaded)" /tmp/sslkeylog_test.log || echo "No SSLKEYLOGFILE messages found"
echo ""
echo "Port filter information:"
grep -E "(Port filter|target_port)" /tmp/sslkeylog_test.log
echo ""
echo "Captured packets:"
grep -E "Captured TLS packet" /tmp/sslkeylog_test.log || echo "No packets captured"
echo ""
echo "TLS records:"
grep -E "TLS Record" /tmp/sslkeylog_test.log || echo "No TLS records found"
echo ""
echo "Decryption attempts:"
grep -E "(Decrypted|decrypt|Failed to decrypt)" /tmp/sslkeylog_test.log || echo "No decryption attempts found"
echo ""
echo "BPF debug output:"
grep -E "BPF:" /tmp/sslkeylog_test.log | tail -10 || echo "No BPF debug output"

# Clean up
rm -f /tmp/sslkeylog_test.log $SSLKEYLOGFILE
