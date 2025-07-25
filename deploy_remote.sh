#!/bin/bash

# Deploy script for TLS capture tool to remote Linux host

# Remote host information
REMOTE_HOST="192.168.64.12"
REMOTE_USER="root"

# Build locally first (optional, can be done on remote as well)
echo "Building project locally (optional)..."
make clean

# Copy files to remote host
echo "Copying files to remote host..."
scp -r src/ Makefile common.h tls_capture.bpf.c tls_capture.c packet_parser.c ssl_hooks.c crypto_utils.c http_parser.c tls_decryption.c ${REMOTE_USER}@${REMOTE_HOST}:~/tls-capture/

# SSH to remote host and build
echo "Building on remote host..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "cd ~/tls-capture && make clean && make"

echo "Deployment complete!"
