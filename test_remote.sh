#!/bin/bash

# Script to deploy and test the code on the remote host

# Create a new directory for testing
ssh root@192.168.64.12 "mkdir -p /root/tls-capture-test"

# Copy all files to the remote host
echo "Copying files to remote host..."
scp -r src root@192.168.64.12:/root/tls-capture-test/
scp Makefile root@192.168.64.12:/root/tls-capture-test/
scp README.md root@192.168.64.12:/root/tls-capture-test/
scp PROJECT_SUMMARY.md root@192.168.64.12:/root/tls-capture-test/
scp .specs/technical-design.md root@192.168.64.12:/root/tls-capture-test/

# Build on the remote host
echo "Building on remote host..."
ssh root@192.168.64.12 "cd /root/tls-capture-test && make clean && make"

echo "Deployment and build completed."
