# Task Description for Continuing TLS Traffic Capture Tool Development

## Project Overview

You are continuing work on a **TLS Traffic Capture and Decryption Tool** for Linux platforms. This tool captures TLS/HTTPS traffic in real-time and decrypts encrypted packets into plain text using eBPF (Extended Berkeley Packet Filter) technology.

### Project Goals

The ultimate goal is to create a production-ready tool that can:
1. Capture TLS/HTTPS traffic in real-time using eBPF XDP
2. Extract SSL/TLS keys from running applications (OpenSSL, GnuTLS, NSS)
3. Decrypt TLS 1.2/1.3 traffic using extracted keys
4. Output decrypted content in human-readable format
5. Generate PCAP files with decrypted content
6. Have minimal performance impact on the system

## Project Structure

```
tls-capture-tool/
├── README.md                          # User documentation
├── PROJECT_SUMMARY.md                # Implementation summary
├── TLS_Traffic_Capture_Tool_Design.md # Technical design document
├── FINAL_SUMMARY.md                   # Current status summary
├── Makefile                          # Build system
├── src/
│   ├── tls_capture.bpf.c             # ✅ Working BPF program (core functionality)
│   ├── tls_capture.c                 # ✅ Userspace application
│   ├── tls_capture.h                # Header definitions
│   ├── common.h                      # Common structures
│   ├── simple_bpf_types.h            # BPF type definitions
│   ├── ssl_hooks.c                   # SSL hooking logic (needs implementation)
│   ├── crypto_utils.c                # Cryptographic utilities (needs enhancement)
│   ├── packet_parser.c              # Packet parsing (needs enhancement)
│   └── tls_analyzer_demo.c           # MVP demonstration
└── build_remote.sh                   # Remote deployment script
```

## What Needs to Be Implemented

### 1. SSL Key Extraction Mechanisms

**Priority: HIGH**

Implement uprobe-based SSL library hooking to extract encryption keys:

**Files to modify:**
- `src/ssl_hooks.c` - Main implementation
- `src/tls_capture.bpf.c` - Add uprobe support

**Requirements:**
- Hook into OpenSSL functions (`SSL_write`, `SSL_read`, `SSL_get_session`)
- Extract master secrets and session keys
- Store keys in BPF maps for association with flows
- Support multiple SSL libraries (OpenSSL, GnuTLS, NSS)
- Handle different SSL library versions

**Implementation approach:**
1. Use `bpf_uprobe` to hook SSL library functions
2. Extract key material from SSL session structures
3. Store keys in `key_map` BPF map
4. Associate keys with specific flows using `flow_key`

### 2. Packet Decryption Algorithms

**Priority: HIGH**

Implement TLS 1.2/1.3 decryption algorithms:

**Files to modify:**
- `src/crypto_utils.c` - Main implementation
- `src/tls_capture.c` - Integration with userspace processing

**Requirements:**
- Implement AES-GCM decryption for TLS 1.2/1.3
- Implement ChaCha20-Poly1305 decryption
- Add TLS key derivation functions (PRF for TLS 1.2, HKDF for TLS 1.3)
- Handle packet reassembly for fragmented TLS records
- Support multiple cipher suites

**Implementation approach:**
1. Use OpenSSL EVP APIs for decryption
2. Implement key derivation based on extracted master secrets
3. Handle different TLS versions appropriately
4. Add packet reassembly for fragmented records

### 3. Userspace Processing Enhancements

**Priority: MEDIUM**

Enhance the userspace application to process captured packets:

**Files to modify:**
- `src/tls_capture.c` - Main processing loop
- `src/packet_parser.c` - Packet parsing logic

**Requirements:**
- Implement ring buffer polling for packet reception
- Add packet analysis and decryption
- Implement output formatting (plaintext, JSON, PCAP)
- Add filtering and search capabilities

**Implementation approach:**
1. Poll ring buffer for captured packets
2. Look up SSL keys for each flow
3. Decrypt packet payloads using extracted keys
4. Format and output decrypted content

### 4. Advanced Features

**Priority: LOW**

Additional features for production readiness:

**Files to modify:**
- Various files as needed

**Requirements:**
- Add PCAP file generation with decrypted content
- Add support for multiple network interfaces
- Implement process-specific SSL key targeting

## How to Test and Debug

### Local Development Environment

remember that the local computer is a Mac and you should test and debug the code on a remote Linux environment (see bellow section).

### Remote Testing Environment

The project is designed to run on ARM64 Linux targets. Use the provided scripts:

1. **Deploy to remote host:**
   ```bash
   ./deploy_remote.sh
   ```

2. **Build on remote host:**
   ```bash
   ssh root@192.168.64.12 "cd /root/tls-capture && make clean && make"
   ```

3. **Test on remote host:**
   ```bash
   ssh root@192.168.64.12 "cd /root/tls-capture && sudo ./tls_capture -i enp0s1"
   ```

4. **Generate test traffic:**
   ```bash
   curl -k https://httpbin.org/get
   ```

remember don't directly write code via SSH to remote host, instead, write the code file locally and then scp it to the remote host

### Debugging BPF Programs

1. **Check BPF program loading:**
   ```bash
   bpftool prog list
   ```

2. **View BPF map contents:**
   ```bash
   bpftool map dump name flow_map
   bpftool map dump name key_map
   ```

3. **Monitor ring buffer:**
   ```bash
   bpftool ringbuf list
   ```

### Debugging SSL Hooking

1. **Use uprobe debugging:**
   ```bash
   perf probe -x /lib/x86_64-linux-gnu/libssl.so.1.1 SSL_write
   ```

2. **Check uprobe attachments:**
   ```bash
   cat /sys/kernel/debug/tracing/uprobes
   ```

## Documentation Updates

**Always update documentation when making major changes:**

1. **README.md** - User-facing documentation
2. **TLS_Traffic_Capture_Tool_Design.md** - Technical design
3. **PROJECT_SUMMARY.md** - Implementation summary
4. **FINAL_SUMMARY.md** - Current status

**When updating documentation:**
- Reflect current implementation status
- Update usage examples
- Document new features and capabilities
- Note any changes to build or deployment process

## Development Best Practices

### Code Quality
- Follow existing code style and patterns
- Add proper error handling and logging
- Use secure coding practices
- Write modular, testable code

### Testing
- Test with real HTTPS traffic
- Verify compatibility with different SSL libraries
- Validate decrypted output correctness

### Security
- Handle keys securely in memory
- Document security considerations

## Getting Started

1. **Review existing code:**
   - Study `src/tls_capture.bpf.c` for BPF implementation
   - Examine `src/tls_capture.c` for userspace application
   - Review design documents for technical context

2. **Set up development environment:**
   - Install required dependencies
   - Configure remote testing environment
   - Verify build and deployment process

3. **Start with SSL key extraction:**
   - Begin implementing `src/ssl_hooks.c`
   - Add uprobe support to BPF program
   - Test with simple OpenSSL applications

4. **Iterative development:**
   - Implement features incrementally
   - Test each component thoroughly
   - Document progress and challenges
   - Update documentation regularly

## Resources

- **eBPF Documentation**: https://ebpf.io/
- **libbpf Documentation**: https://github.com/libbpf/libbpf
- **OpenSSL Documentation**: https://www.openssl.org/docs/
- **BPF Reference Guide**: https://cilium.readthedocs.io/en/stable/bpf/
- **XDP Documentation**: https://www.kernel.org/doc/html/latest/networking/xfrm_proc.html

Remember to always test your changes thoroughly and update documentation when making major modifications.