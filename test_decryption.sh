#\!/bin/bash

echo "Testing TLS capture with decryption..."

# Clean up any existing processes
sudo pkill -f tls_capture 2>/dev/null || true
sleep 1

# Generate fresh SSL keys
export SSLKEYLOGFILE=/tmp/sslkeylog_test.txt
rm -f $SSLKEYLOGFILE

echo "Starting TLS capture in background..."
sudo timeout 15s ./tls_capture -P 443 > /tmp/capture_test.log 2>&1 &
CAPTURE_PID=$\!

echo "Waiting for capture to start..."
sleep 3

echo "Generating HTTPS traffic..."
curl -k https://httpbin.org/get --max-time 10 > /tmp/curl_output.txt 2>&1

echo "Waiting for capture to complete..."
sleep 5

echo "=== Capture Results ==="
if [ -f /tmp/capture_test.log ]; then
    echo "Capture log size: $(wc -l < /tmp/capture_test.log) lines"
    echo "First 20 lines of capture:"
    head -20 /tmp/capture_test.log
    echo ""
    echo "Packets captured from port 443:"
    grep -c "443.*->.*443\ < /dev/null | 443.*<-.*443" /tmp/capture_test.log || echo "0"
    echo "Packets captured from port 47873:"
    grep -c "47873" /tmp/capture_test.log || echo "0"
else
    echo "No capture log found"
fi

echo ""
echo "=== SSL Key Log ==="
if [ -f $SSLKEYLOGFILE ]; then
    echo "SSL keys generated: $(wc -l < $SSLKEYLOGFILE) entries"
    tail -3 $SSLKEYLOGFILE
else
    echo "No SSL key log found"
fi

echo ""
echo "=== CURL Output ==="
if [ -f /tmp/curl_output.txt ]; then
    echo "CURL completed successfully:"
    cat /tmp/curl_output.txt | head -5
else
    echo "No CURL output found"
fi

# Clean up
sudo pkill -f tls_capture 2>/dev/null || true
