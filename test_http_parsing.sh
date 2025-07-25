#!/bin/bash

# Test HTTP parsing functionality
echo "=== Testing HTTP Parsing Functionality ==="

# Create a test with simulated HTTP content
echo "Testing HTTP request parsing..."

# Test the HTTP parsing functions directly by creating a simple test
cat > test_http_content.c << 'TESTEOF'
#include "tls_capture.h"

int main() {
    // Test HTTP request
    const char *http_request = "GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent\r\n\r\nThis is the body content";
    
    printf("Testing HTTP request parsing:\n");
    if (is_http_request(http_request, strlen(http_request))) {
        printf("✓ HTTP request detected\n");
        parse_and_display_http(http_request, strlen(http_request));
    } else {
        printf("✗ HTTP request not detected\n");
    }
    
    // Test HTTP response
    const char *http_response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"message\": \"Hello World\"}";
    
    printf("\nTesting HTTP response parsing:\n");
    if (is_http_response(http_response, strlen(http_response))) {
        printf("✓ HTTP response detected\n");
        parse_and_display_http(http_response, strlen(http_response));
    } else {
        printf("✗ HTTP response not detected\n");
    }
    
    return 0;
}
TESTEOF

# Compile the test
clang -I src test_http_content.c src/tls_capture.c src/ssl_hooks.c src/crypto_utils.c src/packet_parser.c -o test_http_content -lbpf -lssl -lcrypto -lpthread -lpcap 2>/dev/null

if [ -f test_http_content ]; then
    echo "Running HTTP parsing test..."
    ./test_http_content
    rm -f test_http_content test_http_content.c
else
    echo "Failed to compile HTTP test"
fi

echo ""
echo "=== HTTP Parsing Test Complete ==="
