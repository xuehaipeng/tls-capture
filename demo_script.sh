#!/bin/bash

# Demo script for TLS Traffic Capture Tool

echo "=== TLS Traffic Capture Tool Demo ==="
echo ""

echo "1. Building the tool..."
cd /root/tls-capture
make clean
make

echo ""
echo "2. Checking build outputs..."
ls -la tls_capture.bpf.o tls_capture

echo ""
echo "3. Showing help message..."
./tls_capture -h

echo ""
echo "4. Running tool demonstration..."
echo "   Note: The tool will run for 5 seconds and then exit automatically"
echo ""

# Detach any existing XDP program
bpftool net detach xdp dev lo 2>/dev/null || true

# Run the tool for 5 seconds
timeout 5s ./tls_capture -i lo -f simple_tls_capture.bpf.o || true

echo ""
echo "=== Demo Complete ==="
echo ""
echo "The TLS Traffic Capture Tool is now functional with:"
echo "- BPF program loading and attachment to network interfaces"
echo "- Basic XDP packet processing (currently passes all packets)"
echo "- Framework for future TLS packet capture and decryption"
echo ""
echo "Next steps for full implementation:"
echo "1. Implement actual TLS packet filtering in XDP program"
echo "2. Add SSL key extraction mechanisms"
echo "3. Implement packet decryption algorithms"
echo "4. Add userspace packet analysis and output formatting"
