#!/bin/bash

# Demo script to test the TLS capture tool

echo "=== TLS Capture Tool Demo ==="
echo ""

echo "1. Building the MVP tool..."
make -f Makefile.mvp clean
make -f Makefile.mvp mvp

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo ""
echo "2. Tool built successfully! Here's the help:"
echo ""
./tls_capture_mvp -h

echo ""
echo "3. To test the tool, run in another terminal:"
echo "   sudo ./tls_capture_mvp -i lo"
echo ""
echo "4. Then generate some HTTPS traffic:"
echo "   curl -k https://httpbin.org/get"
echo "   curl -k https://example.com"
echo ""
echo "5. The tool will capture and analyze TLS packets, showing:"
echo "   - Packet metadata (source/destination, ports, timing)"
echo "   - TLS record analysis (handshake, application data, etc.)"
echo "   - Simulated decryption output"
echo ""
echo "Note: This MVP uses libpcap instead of eBPF for simplicity."
echo "      It demonstrates the core TLS analysis concepts."
echo ""
echo "=== Demo Complete ==="