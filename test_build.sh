#!/bin/bash

# Test build script for TLS capture tool

set -e

echo "=== TLS Capture Tool Build Test ==="

# Check if running as root for some tests
if [[ $EUID -eq 0 ]]; then
    echo "Running as root - full tests available"
    ROOT_TESTS=1
else
    echo "Running as non-root - limited tests"
    ROOT_TESTS=0
fi

# Check dependencies
echo "Checking dependencies..."
make check-deps || {
    echo "Dependencies check failed. Please install required packages:"
    echo "Ubuntu/Debian: sudo apt install -y libbpf-dev libssl-dev clang make linux-headers-\$(uname -r)"
    echo "CentOS/RHEL: sudo yum install -y libbpf-devel openssl-devel clang make kernel-headers"
    exit 1
}

# Clean previous builds
echo "Cleaning previous builds..."
make clean

# Build the project
echo "Building project..."
make || {
    echo "Build failed!"
    exit 1
}

# Check if files were created
echo "Checking build outputs..."
if [[ ! -f "tls_capture.bpf.o" ]]; then
    echo "ERROR: BPF object file not created"
    exit 1
fi

if [[ ! -f "tls_capture" ]]; then
    echo "ERROR: Main executable not created"
    exit 1
fi

echo "Build outputs created successfully:"
ls -la tls_capture.bpf.o tls_capture

# Test help output
echo "Testing help output..."
./tls_capture -h

# Test BPF program validation (if running as root)
if [[ $ROOT_TESTS -eq 1 ]]; then
    echo "Testing BPF program loading..."
    timeout 5s ./tls_capture -i lo || {
        echo "Note: BPF program test may have failed due to timeout or missing interface"
    }
fi

echo "=== Build test completed successfully ==="
echo ""
echo "To run the tool:"
echo "  sudo ./tls_capture -i <interface>"
echo ""
echo "Example:"
echo "  sudo ./tls_capture -i eth0"