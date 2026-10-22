#!/usr/bin/env python3
"""Local Mock HTTP Server for Testing the Automated Web Security Scanner.

Provides predefined endpoints with known security header and CORS configurations:
  - http://localhost:8080/secure          (Hardened headers, strict CORS)
  - http://localhost:8080/vulnerable      (Missing headers, dangerous wildcard CORS)
  - http://localhost:8080/cors-reflected  (Reflects incoming Origin header)
  - http://localhost:8080/                (Index with documentation)

Use this server to test scanner behavior safely and reproducibly offline.
"""
from __future__ import annotations

import argparse
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler


class MockSecurityHandler(BaseHTTPRequestHandler):
    server_version = "MockTestServer/1.0"

    def log_message(self, format, *args):
        # Clean logging format
        sys.stdout.write(f"[TEST SERVER] {self.address_string()} - {format % args}\n")
        sys.stdout.flush()

    def do_HEAD(self):
        self.handle_request(is_head=True)

    def do_GET(self):
        self.handle_request(is_head=False)

    def do_OPTIONS(self):
        path = self.path.split("?")[0].rstrip("/")
        origin = self.headers.get("Origin", "")

        if path == "/secure":
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "https://trusted.example.com")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "86400")
            self.end_headers()
        elif path == "/vulnerable":
            # Dangerous combination: wildcard + credentials
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.end_headers()
        elif path == "/cors-reflected":
            # Dangerous reflection of unvalidated origin
            self.send_response(200)
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Vary", "Origin")
            self.end_headers()
        else:
            # Default: no CORS headers
            self.send_response(204)
            self.end_headers()

    def handle_request(self, is_head: bool = False):
        path = self.path.split("?")[0].rstrip("/")
        if not path:
            path = "/"

        if path == "/secure":
            content = b"<html><body><h1>Secure Endpoint</h1><p>All recommended headers present.</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            # Hardened security headers
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none';")
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
            self.send_header("Access-Control-Allow-Origin", "https://trusted.example.com")
            self.end_headers()
            if not is_head:
                self.wfile.write(content)

        elif path == "/vulnerable":
            content = b"<html><body><h1>Vulnerable Endpoint</h1><p>Missing security headers & loose CORS.</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            # Intentionally omit CSP, HSTS, X-Content-Type-Options, X-Frame-Options, etc.
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            if not is_head:
                self.wfile.write(content)

        elif path == "/cors-reflected":
            content = b"<html><body><h1>Origin Reflection Endpoint</h1></body></html>"
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            if not is_head:
                self.wfile.write(content)

        else:
            content = (
                b"<html><body>"
                b"<h1>Web Security Scanner - Mock Target Server</h1>"
                b"<p>Available test endpoints:</p>"
                b"<ul>"
                b"<li><a href='/secure'>/secure</a> - Fully configured security headers and strict CORS</li>"
                b"<li><a href='/vulnerable'>/vulnerable</a> - Missing headers and wildcard CORS (*)</li>"
                b"<li><a href='/cors-reflected'>/cors-reflected</a> - Reflects request Origin</li>"
                b"</ul>"
                b"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            if not is_head:
                self.wfile.write(content)


def run_server(host: str = "127.0.0.1", port: int = 8080):
    server_address = (host, port)
    httpd = HTTPServer(server_address, MockSecurityHandler)
    print(f"[*] Mock Security Test Server running at http://{host}:{port}/")
    print(f"[*] Test endpoints:")
    print(f"    - Hardened:    http://{host}:{port}/secure")
    print(f"    - Misconfigured: http://{host}:{port}/vulnerable")
    print(f"    - Reflected CORS: http://{host}:{port}/cors-reflected")
    print("[*] Press Ctrl+C to stop.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping server...")
    finally:
        httpd.server_close()
        print("[*] Server stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock server for web security scanner testing.")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port number (default: 8080)")
    args = parser.parse_args()
    run_server(args.host, args.port)
