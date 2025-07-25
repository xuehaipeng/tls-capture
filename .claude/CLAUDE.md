# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a TLS/HTTPS traffic capture and decryption tool built with eBPF technology for Linux. It can capture encrypted TLS packets and decrypt them into plain text using SSL key extraction.

## Architecture

The tool consists of three main components:

1. **XDP Program (BPF)** - Kernel-space component that intercepts network packets
   - File: `src/tls_capture.bpf.c`
   - Captures TLS packets at the kernel level using XDP
   - Uses BPF maps for flow tracking and key storage
   - Sends captured packets to userspace via ring buffer

2. **Userspace Application** - Main application that controls the capture process
   - File: `src/tls_capture.c`
   - Loads and attaches the BPF program
   - Handles command-line arguments
   - Processes captured packets and performs decryption
   - Manages SSL key extraction hooks

3. **SSL Hooks** - Component that extracts encryption keys from SSL libraries
   - Files: `src/ssl_hooks.c`, `src/crypto_utils.c`, `src/packet_parser.c`
   - Hooks into OpenSSL functions to extract master secrets
   - Implements TLS 1.2/1.3 key derivation
   - Performs AES-GCM decryption

## Build Commands

```bash
# Check dependencies
make check-deps

# Build the tool
make

# Clean build artifacts
make clean
```

## Key Dependencies

- Linux kernel 5.15+
- libbpf-dev
- libssl-dev
- clang
- make

## Development Commands

### Testing
```bash
# Run basic test
sudo ./test_tool.sh

# Test with curl
curl -k https://httpbin.org/get

# Test with specific process
sudo ./tls_capture -i lo -p $(pgrep curl)
```

### Running
```bash
# Basic usage
sudo ./tls_capture -i eth0

# Capture specific port with key extraction
sudo ./tls_capture -i eth0 -p <process_id> -P 8443

# Write to PCAP file
sudo ./tls_capture -i eth0 -w capture.pcap
```

## Key Data Structures

Shared between kernel and userspace:
- `flow_key` - Identifies network flows
- `packet_info` - Contains captured packet data
- `ssl_key_info` - Stores SSL encryption keys
- `flow_state` - Tracks flow state information

## BPF Maps

- `flow_map` - Tracks network flow state
- `key_map` - Stores extracted SSL keys
- `packet_ringbuf` - Ring buffer for packet data transfer