#!/bin/bash

# Test script for enhanced TLS capture tool

set -e

echo "=== Testing Enhanced TLS Capture Tool ==="

# Check if running on Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "This script must be run on a Linux system"
    exit 1
fi

# Check if the tool is built
if [[ ! -f "tls_capture" ]] || [[ ! -f "simple_tls_capture.bpf.o" ]] || [[ ! -f "complete_tls_capture.bpf.o" ]]; then
    echo "Tool not built. Please build it first with 'make'"
    exit 1
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

echo "Available network interfaces:"
ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' '

# Test 1: Basic functionality with simple BPF program
echo "=== Test 1: Basic functionality with simple BPF program ==="
timeout 5s ./tls_capture -i lo -f simple_tls_capture.bpf.o || true

# Test 2: Enhanced functionality with complete BPF program
echo "=== Test 2: Enhanced functionality with complete BPF program ==="
timeout 5s ./tls_capture -i lo -f complete_tls_capture.bpf.o || true

# Test 3: Test with PID targeting (if curl is available)
if command -v curl &> /dev/null; then
    echo "=== Test 3: Testing with PID targeting ==="
    # Start a background curl process
    curl -k https://httpbin.org/get &
    CURL_PID=$!
    
    # Give it a moment to start
    sleep 1
    
    # Run the tool targeting the curl process
    timeout 3s ./tls_capture -i lo -p $CURL_PID || true
    
    # Kill the curl process if it's still running
    kill $CURL_PID 2>/dev/null || true
    wait $CURL_PID 2>/dev/null || true
else
    echo "curl not available, skipping PID targeting test"
fi

echo "=== All tests completed ==="
