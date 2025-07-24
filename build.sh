#!/bin/bash

# Simple build script for TLS capture tool

set -e

echo "=== Building TLS Capture Tool ==="

# Check if running on Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "This script must be run on a Linux system"
    exit 1
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

echo "=== Build completed successfully ==="
