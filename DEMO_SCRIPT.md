# TLS Capture Tool - Demo Script

This script demonstrates the current working functionality of the TLS Capture Tool.

## Prerequisites

1. Linux system with eBPF support (kernel 5.15+)
2. Root privileges
3. Required dependencies installed:
   - libbpf-dev
   - libssl-dev
   - clang
   - make

## Setup

```bash
# Clone the repository
git clone <repository_url>
cd tls-capture-tool

# Build the tool
make clean
make

# Check dependencies
make check-deps
```

## Demo 1: Basic Port Filtering

This demo shows that port filtering is working correctly.

```bash
# Terminal 1: Start TLS capture on port 443
sudo ./tls_capture -i enp0s1 -P 443

# Terminal 2: Generate HTTPS traffic on port 443 (should be captured)
curl -k https://httpbin.org:443/get

# Terminal 2: Generate HTTP traffic on port 80 (should be filtered out)
curl http://httpbin.org:80/get
```

Expected output:
- Traffic on port 443 is captured and displayed
- Traffic on port 80 is filtered out and not displayed

## Demo 2: SSLKEYLOGFILE Monitoring

This demo shows that SSLKEYLOGFILE monitoring is working.

```bash
# Terminal 1: Set up SSLKEYLOGFILE and start capture
export SSLKEYLOGFILE=/tmp/sslkeys.txt
SSLKEYLOGFILE=/tmp/sslkeys.txt sudo ./tls_capture -i enp0s1 -P 443

# Terminal 2: Generate HTTPS traffic with key logging
SSLKEYLOGFILE=/tmp/sslkeys.txt curl -k https://httpbin.org:443/get
```

Expected output:
- SSLKEYLOGFILE is monitored and parsed
- SSL keys are read from the file
- Keys are stored in BPF maps for decryption

## Demo 3: PCAP File Generation

This demo shows that PCAP file generation is working.

```bash
# Terminal 1: Start TLS capture with PCAP output
sudo ./tls_capture -i enp0s1 -P 443 -w capture.pcap

# Terminal 2: Generate HTTPS traffic
curl -k https://httpbin.org:443/get

# Terminal 1: Stop capture with Ctrl+C

# Terminal 3: Analyze PCAP file with Wireshark
wireshark capture.pcap
```

Expected output:
- Captured packets are saved to capture.pcap
- PCAP file can be opened and analyzed with Wireshark
- TLS packets are visible in the PCAP file

## Demo 4: Multiple Port Capture

This demo shows that multiple ports can be captured.

```bash
# Terminal 1: Start TLS capture on multiple ports
sudo ./tls_capture -i enp0s1 -P 443,8443

# Terminal 2: Generate traffic on both ports
curl -k https://httpbin.org:443/get
curl -k https://httpbin.org:8443/get
```

Expected output:
- Traffic on both ports 443 and 8443 is captured
- Traffic on other ports is filtered out

## Key Features Demonstrated

### ✅ Port Filtering
- Traffic is filtered based on specified ports
- Non-target ports are correctly filtered out
- BPF program applies filtering at kernel level for efficiency

### ✅ SSLKEYLOGFILE Monitoring
- SSL key log files are monitored and parsed
- Keys are extracted and stored in BPF maps
- Existing keys in SSLKEYLOGFILE are read and used

### ✅ TLS Packet Capture
- TLS packets are captured in real-time
- TLS records are parsed and analyzed
- Flow tracking is implemented with BPF maps

### ✅ PCAP File Generation
- Captured packets can be saved to PCAP files
- Files are compatible with Wireshark and other analysis tools
- Header information is correctly written

### ✅ Multi-port Support
- Multiple ports can be specified for capture
- Traffic on all specified ports is captured
- Efficient filtering reduces unnecessary processing

## Current Limitations

### ⏳ SSL Key Extraction
- Real-time SSL key extraction from running applications is not fully implemented
- Requires eBPF uprobe attachment to SSL functions
- Current implementation has placeholder functions

### ⏳ TLS Decryption
- Full TLS decryption to plaintext HTTP content is not yet implemented
- Requires real SSL keys for decryption
- Current implementation can read pre-existing keys from SSLKEYLOGFILE

## Future Enhancements

### 1. Complete SSL Key Extraction
- Implement eBPF uprobe attachment to SSL_write/SSL_read functions
- Enable real-time SSL key extraction from running applications
- Support for multiple SSL libraries (OpenSSL, GnuTLS, NSS)

### 2. Full TLS Decryption
- Implement AES-GCM, ChaCha20-Poly1305 decryption
- Support for TLS 1.2 and 1.3 key derivation
- HTTP content parsing from decrypted data

### 3. Advanced Features
- Packet reassembly for fragmented traffic
- Support for ChaCha20-Poly1305 decryption
- Advanced SSL library support (GnuTLS, NSS)
- PCAP file generation with decrypted content
- HTTP/2 and HTTP/3 analysis

## Security Considerations

⚠️ **Important Security Notes:**

- This tool requires root privileges to load eBPF programs
- It can decrypt TLS traffic, which has privacy implications
- Only use on networks and systems you own or have explicit permission to monitor
- Ensure compliance with local laws and regulations
- Keys and decrypted data are handled in memory - ensure secure system practices

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Ensure you're running as root
   sudo ./tls_capture
   ```

2. **Interface Not Found**
   ```bash
   # List available interfaces
   ip link show
   # Use correct interface name
   sudo ./tls_capture -i eth0
   ```

3. **No Packets Captured**
   - Ensure there's TLS traffic on the specified interface
   - Check firewall rules
   - Verify the target application is using OpenSSL

4. **SSL Key Extraction Fails**
   - Ensure SSLKEYLOGFILE is set correctly
   - Verify the target application supports SSLKEYLOGFILE
   - Check file permissions on SSLKEYLOGFILE

### Debug Information

```bash
# Check BPF program status
sudo bpftool prog list | grep xdp

# Monitor BPF maps
sudo bpftool map dump name key_map

# View kernel logs
dmesg | grep BPF
```

## Conclusion

The TLS Capture Tool provides a powerful foundation for TLS traffic analysis with working core functionality including port filtering, SSLKEYLOGFILE monitoring, TLS packet capture, and PCAP file generation. With the planned enhancements, it will become a complete solution for TLS traffic capture and decryption.
