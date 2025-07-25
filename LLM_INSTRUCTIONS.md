# Instructions for Continuing TLS Traffic Capture Tool Development

## Project Background

This is a Linux-based tool that captures TLS/HTTPS traffic and decodes encrypted packets into plain text using eBPF (Extended Berkeley Packet Filter) technology. The tool consists of two main components:

1. A BPF program that runs in kernel space to capture network packets
2. A userspace application that processes captured packets and attempts to decrypt TLS traffic

## Technical Design

### Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   XDP Program   │    │  Uprobe Program │    │  Userspace App  │
│                 │    │                 │    │                 │
│ • Packet Filter│────│ • Key Extraction│────│ • Decryption    │
│ • Flow Tracking│    │ • SSL Hooks     │    │ • Reassembly    │
│ • Metadata     │    │ • Context Track │    │ • Output        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   eBPF Maps     │
                    │                 │
                    │ • Flow Table    │
                    │ • Key Store     │
                    │ • Packet Buffer │
                    │ • Statistics    │
                    └─────────────────┘
```

### Key Components

1. **BPF Program** (`src/tls_capture.bpf.c`):
   - Uses XDP to capture network packets at the kernel level
   - Filters for TLS traffic on ports 443 and 8443
   - Stores packet metadata and payload in eBPF maps
   - Uses a ring buffer to transfer data to userspace

2. **Userspace Application** (`src/tls_capture.c`):
   - Loads and attaches the BPF program
   - Processes packets received from the ring buffer
   - Attempts to decrypt TLS packets using SSL keys
   - Displays decrypted content in human-readable format

3. **SSL Hooking** (`src/ssl_hooks.c`):
   - Hooks into SSL library functions to extract encryption keys
   - Stores keys in eBPF maps for use in decryption

4. **Decryption Engine** (`src/crypto_utils.c`, `src/tls_decryption.c`):
   - Implements TLS decryption algorithms (AES-GCM)
   - Handles key derivation for TLS 1.2 and 1.3

5. **Packet Parsing** (`src/packet_parser.c`, `src/http_parser.c`):
   - Parses TLS record headers
   - Analyzes decrypted content for HTTP traffic
   - Formats output for display

## Current Status and Issues

The tool compiles successfully but has several critical issues that need to be addressed:

### 1. No Output During Capture

When running the tool with:
```bash
sudo ./tls_capture -i enp0s1
```

And generating traffic with:
```bash
curl -k https://httpbin.org/get
```

The tool produces no output. This suggests that either:
- Packets are not being captured correctly
- Packets are not being processed by the userspace application
- There's an issue with the ring buffer communication

### 2. Missing Plaintext Output

For HTTPS packets, we want to see:
- HTTP headers in plaintext
- HTTP body in plaintext (if it exists and is not binary)

Currently, even when packets are captured, the decrypted content is not being properly displayed.

### 3. PCAP File Generation

The tool should be able to save captured traffic to a PCAP file with:
- Plaintext HTTP packets (after decryption)
- Not just raw TCP packets

## How to Test and Debug on the Remote Host

### Accessing the Remote Host

The development environment is on a remote Linux host accessible via:
```bash
ssh root@192.168.64.12
```

The project is located at:
```bash
/root/tls-capture-test/
```

### Building the Project

To build the project on the remote host:
```bash
cd /root/tls-capture-test
make clean
make
```

### Testing the Tool

1. **Basic Capture Test**:
   ```bash
   # Terminal 1: Run the capture tool
   sudo ./tls_capture -i enp0s1
   
   # Terminal 2: Generate traffic
   curl -k https://httpbin.org/get
   ```

2. **Debugging with Kernel Logs**:
   ```bash
   # Check for BPF debug output
   dmesg | tail -50
   
   # Monitor BPF program traces
   bpftool prog tracelog
   ```

3. **Checking BPF Maps**:
   ```bash
   # List BPF maps
   bpftool map list
   
   # Dump map contents
   bpftool map dump name flow_map
   bpftool map dump name key_map
   ```

4. **Network Interface Verification**:
   ```bash
   # Check XDP program attachment
   bpftool net show
   
   # Check interface status
   ip link show enp0s1
   ```

### Debugging Approach

1. **Verify Packet Capture**:
   - Add more debug output to the BPF program
   - Check if packets are being captured and filtered correctly
   - Verify that the ring buffer is functioning

2. **Check Userspace Processing**:
   - Add debug output to the `handle_packet` function
   - Verify that packets are being received from the ring buffer
   - Check SSL key lookup and decryption process

3. **Validate Decryption**:
   - Ensure SSL keys are being extracted correctly
   - Verify that decryption algorithms are working
   - Check HTTP parsing of decrypted content

## Expected Deliverables

1. **Fixed Output Display**:
   - The tool should display captured TLS packets with source/destination IP and port
   - Decrypted HTTP headers should be displayed in plaintext
   - Decrypted HTTP body should be displayed in plaintext (if not binary)

2. **PCAP File Generation**:
   - Add functionality to save captured traffic to a PCAP file
   - The PCAP file should contain decrypted HTTP packets
   - Provide a command-line option to enable PCAP output

3. **Improved Debugging**:
   - Add verbose/debug mode to show more detailed information
   - Include error messages for failed decryption attempts
   - Provide status information about SSL key extraction

## Implementation Hints

1. **Packet Flow Debugging**:
   - Add `bpf_printk` statements in the BPF program to trace packet flow
   - Add `printf` statements in the userspace application to trace processing

2. **SSL Key Extraction**:
   - The current implementation has a placeholder for SSL key extraction
   - You may need to implement actual uprobe-based hooking for SSL functions
   - Consider using `libbpf` uprobe attachment functions

3. **HTTP Content Display**:
   - Use the existing `http_parser.c` functions to analyze decrypted content
   - Format output to clearly distinguish headers from body
   - Handle different content types appropriately

4. **PCAP Generation**:
   - Use `libpcap` library for PCAP file generation
   - Write decrypted packets to PCAP file in standard format
   - Include appropriate headers and metadata

## Testing Verification

After implementing the fixes, verify that:

1. Running `sudo ./tls_capture -i enp0s1` shows output when `curl -k https://httpbin.org/get` is executed
2. The output includes HTTP headers in plaintext
3. The output includes HTTP body in plaintext (when applicable)
4. A PCAP file can be generated with decrypted HTTP content
5. The tool handles various HTTPS traffic scenarios correctly

Remember to test with different types of HTTPS traffic to ensure robustness.
