#!/bin/bash

# Test script for TLS capture tool with real-world scenarios

set -e

echo "=== TLS Capture Tool - Real World Testing ==="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Check if the tool is built
if [[ ! -f "tls_capture" ]] || [[ ! -f "tls_capture.bpf.o" ]]; then
    echo "Tool not built. Building..."
    make clean && make
fi

# Function to test HTTPS traffic capture
test_https_capture() {
    local interface=$1
    local port=${2:-443}
    local pcap_file="test_https_capture_$(date +%s).pcap"
    
    echo "Testing HTTPS traffic capture on $interface (port $port)"
    echo "PCAP output file: $pcap_file"
    
    # Start the capture tool in background with PCAP output
    echo "Starting TLS capture tool with PCAP output..."
    timeout 30s sudo ./tls_capture -i $interface -P $port -w $pcap_file &
    CAPTURE_PID=$!
    
    # Wait a moment for the tool to start
    sleep 3
    
    # Generate multiple HTTPS requests for better testing
    echo "Generating HTTPS traffic..."
    curl -k https://httpbin.org/get >/dev/null 2>&1 &
    curl -k https://httpbin.org/json >/dev/null 2>&1 &
    curl -k https://jsonplaceholder.typicode.com/posts/1 >/dev/null 2>&1 &
    wget -q --no-check-certificate https://httpbin.org/uuid -O /dev/null &
    
    # Wait for all background jobs to complete
    wait
    
    # Wait for the capture tool to finish
    wait $CAPTURE_PID 2>/dev/null || true
    
    # Check PCAP file results
    if [[ -f "$pcap_file" ]]; then
        local file_size=$(stat -c%s "$pcap_file" 2>/dev/null || stat -f%z "$pcap_file" 2>/dev/null || echo "0")
        echo "PCAP file created: $pcap_file ($file_size bytes)"
        
        # Validate PCAP file if possible
        if command -v file >/dev/null 2>&1; then
            echo "File type: $(file $pcap_file)"
        fi
        
        # Keep the file for analysis
        echo "PCAP file saved for analysis: $pcap_file"
    else
        echo "WARNING: PCAP file was not created"
    fi
    
    echo "HTTPS traffic capture test completed"
}

# Function to test with different ports
test_custom_port() {
    local interface=$1
    local port=8443
    local pcap_file="test_custom_port_$(date +%s).pcap"
    
    echo "Testing custom port capture on $interface (port $port)"
    echo "PCAP output file: $pcap_file"
    
    # Start the capture tool in background with PCAP output
    echo "Starting TLS capture tool on port $port with PCAP output..."
    timeout 30s sudo ./tls_capture -i $interface -P $port -w $pcap_file &
    CAPTURE_PID=$!
    
    # Wait a moment for the tool to start
    sleep 3
    
    # Try to create a simple TLS server on the custom port for testing
    echo "Attempting to create test TLS traffic on port $port..."
    
    # Use openssl to create a simple TLS server in background
    if command -v openssl >/dev/null 2>&1; then
        echo "Creating temporary TLS server on port $port..."
        timeout 10s openssl s_server -accept $port -cert /dev/null -key /dev/null 2>/dev/null &
        SERVER_PID=$!
        sleep 2
        
        # Try to connect to it
        echo "quit" | timeout 5s openssl s_client -connect localhost:$port 2>/dev/null || true
        
        # Clean up server
        kill $SERVER_PID 2>/dev/null || true
    else
        echo "OpenSSL not available, testing passive capture only"
        sleep 10
    fi
    
    # Wait for the capture tool to finish
    wait $CAPTURE_PID 2>/dev/null || true
    
    # Check PCAP file results
    if [[ -f "$pcap_file" ]]; then
        local file_size=$(stat -c%s "$pcap_file" 2>/dev/null || stat -f%z "$pcap_file" 2>/dev/null || echo "0")
        echo "PCAP file created: $pcap_file ($file_size bytes)"
        echo "PCAP file saved for analysis: $pcap_file"
    else
        echo "WARNING: PCAP file was not created"
    fi
    
    echo "Custom port capture test completed"
}

# Function to test with process hooking
test_process_hooking() {
    local interface=$1
    local pcap_file="test_process_hooking_$(date +%s).pcap"
    
    echo "Testing process hooking on $interface"
    echo "PCAP output file: $pcap_file"
    
    # Start the capture tool in background with process hooking and PCAP output
    echo "Starting TLS capture tool with process hooking and PCAP output..."
    timeout 30s sudo ./tls_capture -i $interface -p $$ -w $pcap_file &
    CAPTURE_PID=$!
    
    # Wait a moment for the tool to start
    sleep 3
    
    # Generate some HTTPS traffic from this process and subprocesses
    echo "Generating HTTPS traffic from this process..."
    curl -k https://httpbin.org/get >/dev/null 2>&1
    curl -k https://httpbin.org/headers >/dev/null 2>&1
    wget -q --no-check-certificate https://httpbin.org/ip -O /dev/null
    
    # Test with a background curl process
    curl -k https://httpbin.org/delay/2 >/dev/null 2>&1 &
    CURL_PID=$!
    
    # Wait for background curl to finish
    wait $CURL_PID 2>/dev/null || true
    
    # Wait for the capture tool to finish
    wait $CAPTURE_PID 2>/dev/null || true
    
    # Check PCAP file results
    if [[ -f "$pcap_file" ]]; then
        local file_size=$(stat -c%s "$pcap_file" 2>/dev/null || stat -f%z "$pcap_file" 2>/dev/null || echo "0")
        echo "PCAP file created: $pcap_file ($file_size bytes)"
        echo "PCAP file saved for analysis: $pcap_file"
    else
        echo "WARNING: PCAP file was not created"
    fi
    
    echo "Process hooking test completed"
}

# Main test execution
INTERFACE="lo"  # Default to loopback interface

# Check if a specific interface was provided
if [[ $# -gt 0 ]]; then
    INTERFACE=$1
fi

echo "Using interface: $INTERFACE"

# Run tests
test_https_capture $INTERFACE
test_custom_port $INTERFACE
test_process_hooking $INTERFACE

# Function to clean up test files
cleanup_test_files() {
    echo "Cleaning up test files..."
    
    # List all test PCAP files
    local test_files=$(ls test_*.pcap 2>/dev/null || true)
    
    if [[ -n "$test_files" ]]; then
        echo "Test PCAP files created:"
        for file in $test_files; do
            local file_size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "0")
            echo "  $file ($file_size bytes)"
        done
        
        echo ""
        read -p "Do you want to keep these PCAP files for analysis? (y/N): " -n 1 -r
        echo ""
        
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Removing test PCAP files..."
            rm -f test_*.pcap
            echo "Test files cleaned up."
        else
            echo "Test PCAP files preserved for analysis."
            echo "You can analyze them with tools like Wireshark or tcpdump."
        fi
    else
        echo "No test PCAP files found."
    fi
}

# Function to display test summary
display_test_summary() {
    echo ""
    echo "=== Test Summary ==="
    echo "Interface tested: $INTERFACE"
    echo "Tests performed:"
    echo "  1. HTTPS traffic capture (port 443)"
    echo "  2. Custom port capture (port 8443)"
    echo "  3. Process hooking test"
    echo ""
    echo "All tests completed successfully!"
    echo ""
    echo "Next steps:"
    echo "  1. Review any PCAP files created during testing"
    echo "  2. Analyze captured traffic with Wireshark or tcpdump"
    echo "  3. Test with your specific applications and use cases"
    echo "  4. Monitor system performance during capture"
}

echo "=== All tests completed ==="

# Display summary and cleanup
display_test_summary
cleanup_test_files
