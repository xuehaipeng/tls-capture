#!/bin/bash

# Deploy script for TLS capture tool on remote Linux host

set -e

REMOTE_HOST="192.168.64.12"
REMOTE_USER="root"
REMOTE_DIR="/root/tls-capture"

echo "=== Deploying TLS Capture Tool to Remote Host ==="

# Create remote directory
echo "Creating remote directory..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "mkdir -p ${REMOTE_DIR}"

# Transfer essential source files
echo "Transferring source files..."
scp src/tls_capture.bpf.c ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/
scp src/tls_capture.c ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/
scp src/tls_capture.h ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/
scp src/common.h ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/
scp src/simple_bpf_types.h ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/
scp src/ssl_hooks.c ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/
scp src/crypto_utils.c ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/
scp src/packet_parser.c ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/
scp Makefile ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/

echo "Deployment completed successfully!"
echo ""
echo "To build and run the tool on the remote host:"
echo "  ssh ${REMOTE_USER}@${REMOTE_HOST} \"cd ${REMOTE_DIR} && make clean && make\""
echo ""
echo "Example to run:"
echo "  ssh ${REMOTE_USER}@${REMOTE_HOST} \"cd ${REMOTE_DIR} && sudo ./tls_capture -i eth0\""
