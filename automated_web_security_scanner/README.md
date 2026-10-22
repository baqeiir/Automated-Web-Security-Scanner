# Automated Web Security Scanner

**Bootcamp Final Project:** Defensive Python-based HTTP security-header and CORS configuration auditor.

Designed for authorized configuration assessments and educational audits. Evaluates defensive posture against OWASP best practices without invasive testing or exploitation.

---

## Capabilities & Architecture

- **HTTP Security Header Audit:** Checks for the presence and configuration of:
  - `Content-Security-Policy` (CSP)
  - `Strict-Transport-Security` (HSTS)
  - `X-Content-Type-Options` (MIME sniffing prevention)
  - `Referrer-Policy` (Referrer leakage control)
  - `Permissions-Policy` (Browser API restriction)
  - `X-Frame-Options` & CSP `frame-ancestors` (Clickjacking mitigation)
- **CORS Misconfiguration Detection:** Sends an `OPTIONS` preflight probe with a non-routable origin (`https://scanner-test.invalid`) to evaluate:
  - Dangerous wildcard origin reflection combined with credentials (`Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`)
  - Arbitrary origin reflection
  - Missing or permissive CORS headers
- **Multi-Format Reporting:**
  - Machine-readable JSON report (`report.json`)
  - Standalone, responsive HTML dashboard (`report.html`) with risk metric cards, severity badges, and remediation recommendations.
- **Defensive Error Handling:** Gracefully handles invalid URLs, unsupported schemes, timeouts, DNS failures, and TLS handshake errors without unhandled exceptions.
- **Zero Third-Party Dependencies:** Implemented purely in Python 3 standard library (`urllib`, `ssl`, `json`, `argparse`, `unittest`, `http.server`).

---

## Project Structure

```text
automated_web_security_scanner/
│
├── scanner.py             # Main security scanner CLI and reporting engine
├── test_server.py         # Local mock HTTP server with secure & vulnerable endpoints
├── requirements.txt       # Project dependencies (Zero external packages required)
├── README.md              # Documentation, usage guide, and architecture overview
├── REPORT_TEMPLATE.md     # Completed submission report template for bootcamp evaluation
│
└── tests/
    └── test_scanner.py    # 13 comprehensive unit & mock HTTP response tests
```

---

## Quickstart

### Prerequisites
- Python 3.10+ (tested on Python 3.14 on Windows, macOS, and Linux)
- No `pip install` required.

### 1. Run Automated Unit Tests (Offline)

Verify URL normalization, finding data structures, mock HTTP responses, and HTML reporting:

```powershell
python -m unittest discover tests
```
*Expected: 13 tests passing in < 0.05s.*

### 2. Run Local Demonstration Server

To safely test the scanner without scanning external websites or risking unauthorized testing:

```powershell
python test_server.py --port 8080
```
This serves:
- `http://localhost:8080/secure` (Hardened headers, restricted CORS)
- `http://localhost:8080/vulnerable` (Missing headers, wildcard CORS + credentials)
- `http://localhost:8080/cors-reflected` (Reflects request Origin)

### 3. Execute a Scan

In a second terminal window:

**Scan Vulnerable Target (JSON + HTML Report):**
```powershell
python scanner.py http://localhost:8080/vulnerable --output report_vuln.json --html report_vuln.html
```

**Scan Secure Target:**
```powershell
python scanner.py http://localhost:8080/secure --output report_secure.json --html report_secure.html
```

**Scan an Authorized External Domain:**
```powershell
python scanner.py https://example.com --timeout 10 --output report.json --html report.html
```

---

## Safety, Scope, & Ethics

- **Non-Exploitative:** The tool performs only a single `GET` and a single `OPTIONS` request. It never crawls, brute-forces, executes payloads, or bypasses authentication.
- **Authorization Required:** Never scan domains without explicit written authorization. Use the provided `test_server.py` or localhost for demonstrations and labs.
- **Contextual Limitations:**
  - A missing security header represents a defensive gap or sub-optimal configuration, not an automatically exploitable vulnerability.
  - A wildcard CORS header (`*`) on a public, unauthenticated API endpoint may be completely intentional and secure.
  - Automated findings require manual security review and operational context.
