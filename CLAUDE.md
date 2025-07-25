# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Linux-based TLS/HTTPS traffic capture and decryption tool using eBPF technology. The tool captures network packets at the kernel level using XDP (eXpress Data Path), extracts SSL/TLS encryption keys through uprobe-based hooking, and decrypts traffic to display plaintext HTTP content.

## Build and Development Commands

### Dependencies Check
```bash
make check-deps  # Verify all required dependencies are installed
```

### Build
```bash
make clean       # Clean previous build artifacts
make            # Build both BPF program and userspace application
```

### Installation
```bash
make install    # Install to /usr/local/bin (requires sudo)
```

### Running the Tool
```bash
# Basic usage - capture on default interface (eth0)
sudo ./tls_capture

# Capture on specific interface
sudo ./tls_capture -i enp0s1

# Capture on specific port (default: 443 for HTTPS)
sudo ./tls_capture -i eth0 -P 8443

# Capture with SSLKEYLOGFILE for decryption
SSLKEYLOGFILE=/tmp/sslkeys.txt sudo ./tls_capture -i eth0

# Save captured packets to PCAP file
sudo ./tls_capture -i eth0 -w output.pcap

# Use custom BPF object file
sudo ./tls_capture -i eth0 -f custom_tls_capture.bpf.o
```

### Testing and Debugging
```bash
# Generate test HTTPS traffic with key logging
SSLKEYLOGFILE=/tmp/sslkeys.txt curl -k https://httpbin.org/get

# Test decryption with captured keys
SSLKEYLOGFILE=/tmp/sslkeys.txt sudo ./tls_capture -i eth0 -P 443

# Generate traffic on custom port
SSLKEYLOGFILE=/tmp/sslkeys.txt curl -k https://example.com:8443/api

# Check BPF program status
bpftool prog list
bpftool net show

# Monitor BPF maps
bpftool map list
bpftool map dump name flow_map
bpftool map dump name key_map

# View kernel debug output
dmesg | tail -50
```

## Architecture Overview

The project follows a three-tier architecture:

### 1. eBPF Kernel Programs
- **XDP Program** (`src/tls_capture.bpf.c`): Packet capture and filtering at network interface level
- **Uprobe Program**: SSL library function hooking for key extraction (framework exists)
- **BPF Maps**: Data structures for flow tracking, key storage, and packet buffering

### 2. Userspace Application (`src/tls_capture.c`)
- BPF program loading and management
- Ring buffer processing for captured packets
- TLS record parsing and reassembly
- Decryption engine coordination
- Output formatting and PCAP generation

### 3. Core Components
- **SSL Hooks** (`src/ssl_hooks.c`): SSL/TLS key extraction from OpenSSL applications
- **Crypto Utils** (`src/crypto_utils.c`): TLS 1.2/1.3 key derivation and AES-GCM decryption
- **Packet Parser** (`src/packet_parser.c`): TLS record header parsing and validation
- **HTTP Parser** (`src/http_parser.c`): HTTP content analysis from decrypted data
- **TLS Decryption** (`src/tls_decryption.c`): Main decryption engine

## Key Data Structures

### Flow Tracking (`common.h`)
- `struct flow_key`: 5-tuple flow identification (src/dst IP/port, protocol)
- `struct flow_state`: Connection state tracking (sequence numbers, TLS status)
- `struct packet_info`: Captured packet metadata and payload

### TLS Processing
- `struct tls_record_header`: TLS record parsing (type, version, length)
- `struct ssl_key_info`: SSL key material storage (master secret, randoms, cipher suite)

## BPF Maps Usage

The tool uses several eBPF maps for kernel-userspace communication:
- `flow_map`: Active connection tracking
- `key_map`: SSL key storage per connection
- `packet_ringbuf`: High-performance packet data transfer
- `packet_count`: Statistics tracking

## Current Status

✅ **FULLY FUNCTIONAL** - The tool successfully captures TLS traffic and decrypts HTTPS to plaintext HTTP content.

### Key Features Working:
- eBPF XDP packet capture with configurable interface and port filtering
- SSLKEYLOGFILE integration for automatic SSL key extraction
- Full TLS 1.2/1.3 decryption pipeline with AES-GCM support
- HTTP content parsing and display from decrypted TLS data
- PCAP file export for captured traffic
- Real-time TLS traffic analysis and monitoring

### Recent Improvements:
- Added x86_64 architecture support (migrated from ARM64)
- Implemented complete SSLKEYLOGFILE monitoring and parsing
- Enhanced SSL key extraction with automatic key loading
- Integrated TLS decryption with HTTP content detection
- Added comprehensive error handling and user guidance

## Security Considerations

This tool requires root privileges and can decrypt TLS traffic. It should only be used on networks you own or have explicit permission to monitor. Ensure compliance with local laws and regulations.

## Dependencies

- Linux kernel 5.15+ (for eBPF XDP support)
- libbpf-dev (eBPF userspace library)
- libssl-dev (OpenSSL development headers)
- clang (LLVM compiler for BPF)
- libpcap-dev (PCAP file generation)
- linux-headers (kernel headers for BPF compilation)

## Common Issues

### Permission Denied
Ensure running as root: `sudo ./tls_capture`

### BPF Load Failures
- Check kernel version: `uname -r`
- Install kernel headers: `sudo apt install linux-headers-$(uname -r)`
- Verify eBPF support: `cat /boot/config-$(uname -r) | grep BPF`

### No Packet Capture
- Verify interface exists: `ip link show`
- Check for active TLS traffic on the interface
- Ensure target applications use OpenSSL