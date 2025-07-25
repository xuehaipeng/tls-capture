# TLS Capture Tool - Usage Guide

## Overview

This tool provides real-time TLS/HTTPS traffic capture and decryption using eBPF technology. It captures network packets at the kernel level, extracts SSL/TLS encryption keys, and decrypts traffic to display plaintext HTTP content.

## Features

✅ **eBPF XDP Packet Capture** - High-performance kernel-level packet filtering  
✅ **Port-specific Traffic Filtering** - Configurable port targeting  
✅ **SSLKEYLOGFILE Integration** - Automatic SSL key extraction and parsing  
✅ **Real-time TLS Decryption** - Full TLS 1.2/1.3 support with AES-GCM  
✅ **HTTP Content Analysis** - Automatic HTTP parsing from decrypted data  
✅ **PCAP Export** - Save captured traffic for analysis  
✅ **Multi-architecture Support** - Works on x86_64 and ARM64 Linux systems

## Command Line Options

```bash
Usage: ./tls_capture [options]

Options:
  -i <interface>  Network interface to capture on (default: eth0)
  -f <bpf_file>   BPF object file (default: tls_capture.bpf.o)
  -p <pid>        Process ID to hook for SSL keys
  -P <port>       Target port to capture (default: 443, 8443)
  -w <file>       Write captured packets to PCAP file
  -h              Show this help message

Environment Variables:
  SSLKEYLOGFILE   Path to SSL key log file for decryption
```

## Usage Examples

### Basic Usage

```bash
# Capture HTTPS traffic on default ports (443, 8443)
sudo ./tls_capture

# Capture on specific interface
sudo ./tls_capture -i enp0s1

# Capture traffic on custom port
sudo ./tls_capture -P 8080
```

### With SSL Key Logging

```bash
# Set up SSLKEYLOGFILE environment variable
export SSLKEYLOGFILE=/tmp/sslkeys.txt

# Generate HTTPS traffic with key logging
SSLKEYLOGFILE=/tmp/sslkeys.txt curl -k https://httpbin.org/get

# Capture and decrypt the traffic
SSLKEYLOGFILE=/tmp/sslkeys.txt sudo ./tls_capture -i eth0
```

### Advanced Usage

```bash
# Capture custom port with PCAP output
sudo ./tls_capture -i eth0 -P 8443 -w captured_traffic.pcap

# Monitor specific service with SSL key logging
SSLKEYLOGFILE=/var/log/ssl_keys.txt sudo ./tls_capture -P 9443
```

## Real-world Testing Scenarios

### 1. Web Browser Traffic Capture

```bash
# Set up browser with key logging
export SSLKEYLOGFILE=/tmp/browser_keys.txt
firefox &

# In another terminal, start capture
SSLKEYLOGFILE=/tmp/browser_keys.txt sudo ./tls_capture -i eth0

# Visit HTTPS websites in Firefox to see decrypted traffic
```

### 2. API Testing

```bash
# Set up key logging for curl
export SSLKEYLOGFILE=/tmp/api_keys.txt

# Make API calls
curl -k https://api.example.com:8443/data

# Capture and analyze the traffic
SSLKEYLOGFILE=/tmp/api_keys.txt sudo ./tls_capture -P 8443
```

### 3. Application Debugging

```bash
# Monitor specific application port
sudo ./tls_capture -P 3000 -w app_traffic.pcap

# Analyze with Wireshark later
wireshark app_traffic.pcap
```

## Expected Output

When the tool successfully captures and decrypts HTTPS traffic, you'll see output like:

```
TLS Traffic Capture Tool
Interface: eth0
Target Port: 443
Port filter set to: 443
✅ SSLKEYLOGFILE monitoring setup complete
Starting packet capture... Press Ctrl+C to stop

Captured TLS packet: 192.168.1.100:443 -> 192.168.1.50:54321, len=1024
TLS Record: Type=Application Data, Version=TLS 1.2, Length=1019
🔍 TLS Application Data detected (potential HTTP content)
🔓 Decrypted TLS data (512 bytes):
🌐 HTTP Traffic Detected:
=== HTTP CONTENT ===
GET /api/users HTTP/1.1
Host: api.example.com
User-Agent: curl/7.81.0
Accept: */*

HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 156

{"users": [{"id": 1, "name": "John Doe"}]}
=== END HTTP CONTENT ===
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure running as root with `sudo`
2. **Interface not found**: Check available interfaces with `ip link show`
3. **No packets captured**: Verify target applications use specified ports
4. **Decryption fails**: Ensure SSLKEYLOGFILE contains matching keys

### Debug Information

```bash
# Check BPF program status
sudo bpftool prog list | grep xdp

# Monitor BPF maps
sudo bpftool map dump name key_map

# View kernel logs
dmesg | grep BPF
```

## Security Considerations

⚠️ **Important**: This tool requires root privileges and can decrypt TLS traffic. Only use on networks you own or have explicit permission to monitor. Ensure compliance with local laws and regulations.

## Dependencies

- Linux kernel 5.15+ (eBPF XDP support)
- Root privileges
- libbpf-dev, libssl-dev, libpcap-dev
- clang compiler for eBPF programs

## Integration with Other Tools

### Wireshark Analysis
```bash
# Capture to PCAP for detailed analysis
sudo ./tls_capture -i eth0 -w capture.pcap
wireshark capture.pcap
```

### Log Analysis
```bash
# Redirect decrypted content to log file
sudo ./tls_capture -i eth0 2>&1 | tee /var/log/tls_analysis.log
```

This tool provides a powerful foundation for TLS traffic analysis, security research, and network debugging in controlled environments.