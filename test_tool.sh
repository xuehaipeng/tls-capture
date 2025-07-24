#!/bin/bash

# Test script for TLS capture tool

set -e

echo "=== Testing TLS Capture Tool ==="

# Check if running on Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "This script must be run on a Linux system"
    exit 1
fi

# Check if the tool is built
if [[ ! -f "tls_capture" ]] || [[ ! -f "tls_capture.bpf.o" ]]; then
    echo "Tool not built. Please build it first."
    exit 1
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# List available network interfaces
echo "Available network interfaces:"
ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' '

# Test with loopback interface
echo "Testing with loopback interface..."
timeout 10s ./tls_capture -i lo || true

echo "=== Test completed ==="
