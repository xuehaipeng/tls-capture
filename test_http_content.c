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
