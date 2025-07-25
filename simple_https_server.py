#!/usr/bin/env python3
import http.server
import socketserver
import ssl
import os

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>TLS Capture Test Server</title></head><body><h1>Welcome to TLS Capture Test Server</h1><p>This is a test server for capturing HTTPS traffic.</p></body></html>")
        elif self.path == "/api/data":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(b"{\"message\": \"Hello from TLS Capture Test Server\", \"timestamp\": \"2025-07-24T18:45:00Z\", \"data\": {\"id\": 12345, \"name\": \"Test Data\", \"value\": \"sample_value\"}}")
        else:
            super().do_GET()

    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        response = f"{{\"received\": true, \"data\": {{\"message\": \"Data received successfully\", \"received_data\": \"{post_data.decode()}\"}}}}"
        self.wfile.write(response.encode())

if __name__ == "__main__":
    PORT = 8443
    
    # Generate self-signed certificate if it doesn't exist
    if not os.path.exists("server.crt") or not os.path.exists("server.key"):
        os.system("openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'")
    
    with socketserver.TCPServer(("127.0.0.1", PORT), MyHTTPRequestHandler) as httpd:
        httpd.socket = ssl.wrap_socket(httpd.socket, certfile="server.crt", keyfile="server.key", server_side=True)
        print(f"HTTPS Server running on https://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")
