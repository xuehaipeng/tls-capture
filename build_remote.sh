#!/bin/bash

# Build script for TLS capture tool on remote Linux host

set -e

REMOTE_HOST="192.168.64.12"
REMOTE_USER="root"
REMOTE_DIR="/home/xuehaipeng/GolandProjects/tls-capture"

echo "=== Building TLS Capture Tool on Remote Host ==="

# Create remote directory
echo "Creating remote directory..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "mkdir -p ${REMOTE_DIR}"

# Transfer source files
echo "Transferring source files..."
rsync -avz --exclude='.git' --exclude='*.o' --exclude='tls_capture' --exclude='tls_capture_mvp' ./ ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/

# Build on remote host
echo "Building on remote host..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "cd ${REMOTE_DIR} && make clean && make"

echo "Build completed successfully!"
echo ""
echo "To run the tool on the remote host:"
echo "  ssh ${REMOTE_USER}@${REMOTE_HOST} \"cd ${REMOTE_DIR} && sudo ./tls_capture -i <interface>\""
echo ""
echo "Example:"
echo "  ssh ${REMOTE_USER}@${REMOTE_HOST} \"cd ${REMOTE_DIR} && sudo ./tls_capture -i eth0\""
