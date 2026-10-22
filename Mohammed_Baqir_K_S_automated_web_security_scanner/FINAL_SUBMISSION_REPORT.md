# Cybersecurity Bootcamp Final Project Report
# Automated Web Security Scanner (Python)

**Student Name:** Mohammed Baqir K S  
**Project Title:** Automated Web Security Scanner using Python (AWS Scanner) 
**Technical Level:** Beginner to Intermediate (Portfolio-Ready)  
**Submission Date:** 23 October 2026  
**Repository Structure:** Pure Python Standard Library (`scanner.py`, `test_server.py`, `tests/`)

---

## 1. Abstract

Modern web security relies heavily on defense-in-depth mechanisms implemented at the HTTP response level, notably HTTP security headers and Cross-Origin Resource Sharing (CORS) policies. When misconfigured or omitted, web applications become susceptible to client-side attacks such as Cross-Site Scripting (XSS), Clickjacking, MIME-type confusion, and unauthorized cross-origin data exposure.

This project delivers a robust, defensive, and lightweight automated security scanner built in Python without third-party dependencies. The tool inspects HTTP security headers, probes CORS configuration via an RFC-compliant `OPTIONS` preflight simulation, records TLS connection telemetry, and generates structured findings in both JSON and modern HTML formats. The scanner was evaluated against a local mock testbed containing both hardened and misconfigured endpoints, achieving 100% test pass rates across 13 offline unit and mock response tests.

---

## 2. Problem Statement

Security configuration reviews are frequently overlooked in rapid development cycles. Manually querying web endpoints using tools like `curl` or browser developer tools to inspect headers is repetitive, error-prone, and lacks standardized documentation. Conversely, enterprise web application scanners (e.g., OWASP ZAP, Burp Suite Enterprise) are often resource-heavy, complex for junior security analysts, and may trigger network defenses if misconfigured.

There is a clear operational need for a non-intrusive, single-request baseline auditing tool that junior security analysts and developers can run to assess security header compliance and CORS hygiene before production deployment.

---

## 3. Objectives

The primary objectives of this project are:
1. **Target Validation & Normalization:** Safely sanitize user input, enforce HTTP/HTTPS schemes, drop client-side fragments, and prevent credential exposure in URLs.
2. **Security Header Auditing:** Interrogate endpoints for the presence and configuration of six vital protective headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and `X-Frame-Options` / CSP `frame-ancestors`).
3. **CORS Behavior Inspection:** Execute a controlled preflight `OPTIONS` request with an unroutable test origin (`https://scanner-test.invalid`) to detect unsafe wildcard origins (`*`) paired with credentials, as well as arbitrary origin reflection.
4. **Actionable Reporting:** Produce machine-readable JSON findings with severity ratings, recorded evidence, and OWASP-aligned remediation advice, alongside an executive HTML report.
5. **Resilient Error Handling:** Maintain zero-crash stability across DNS failures, network timeouts, invalid schemes, and TLS handshake rejections.
6. **Zero-Dependency Reproducibility:** Ensure native execution on any standard Python 3.10+ installation across Windows, macOS, and Linux without package management overhead.

---

## 4. Scope & Limitations

### In-Scope
- Single-request HTTP `GET` inspection of response status, final URL, response time, and headers.
- Single-request HTTP `OPTIONS` preflight probe evaluating CORS response headers.
- Context-aware validation (e.g., omitting HSTS flags on non-HTTPS endpoints).
- Automated risk classification (High, Medium, Low, Info) and remediation guidance.
- Local reproducible testing environment (`test_server.py`).

### Out-of-Scope (Important Defensive Distinction)
- **Non-Exploitative:** The tool does not test for exploitable vulnerabilities (e.g., active XSS injection, SQLi, authentication bypass).
- **Non-Crawling:** The tool analyzes a single specified route rather than crawling whole domain structures.
- **Contextual Judgment:** A missing header is a defensive deficiency, not proof of active vulnerability. For example, a public read-only weather API using `Access-Control-Allow-Origin: *` is operating by design and is not vulnerable.

---

## 5. Tools & Technologies

| Component | Technology | Rationale |
|---|---|---|
| Programming Language | Python 3.14 (3.10+ compatible) | Clean syntax, universal availability, robust standard library |
| HTTP Networking | `urllib.request`, `urllib.error`, `urllib.parse` | Native networking without external `requests` dependency |
| TLS & Cryptography | `ssl` (default verification context) | Enforces strict X.509 certificate validation by default |
| Testing Framework | `unittest`, `unittest.mock` | Built-in offline unit testing and network isolation |
| Local Server Testbed | `http.server.HTTPServer` | Safe, deterministic testing without unauthorized external scans |
| Report Output | `json`, `html` | Standard machine-readable output + visual HTML reporting |
| Operating System | Windows 11 (PowerShell 7/Windows Terminal) | Target student/evaluator operating environment |

---

## 6. System Architecture & Methodology

The scanning workflow executes sequentially to minimize network footprint and eliminate target strain:

```mermaid
flowchart TD
    A["Raw Target URL Input"] --> B["normalize_url() & Validation"]
    B -->|Invalid URL / Bad Scheme| C["Exit with Code 2 & Error Output"]
    B -->|Valid URL| D["request_once(GET) with TLS Validation"]
    D -->|DNS / Network / SSL Failure| E["Record Connection Finding & Output JSON"]
    D -->|HTTP 200/4xx/5xx Response| F["Extract Response Headers & Timing"]
    F --> G["Audit Security Headers<br/>(CSP, HSTS, XFO, Sniffing, Referrer)"]
    G --> H["request_once(OPTIONS)<br/>with Origin: https://scanner-test.invalid"]
    H --> I["Evaluate CORS Misconfigurations<br/>(Wildcard, Credentials, Reflection)"]
    I --> J["Aggregate Findings & Calculate Risk Summary"]
    J --> K["Generate report.json"]
    J --> L["Generate report.html (Optional)"]
    J --> M["Print Formatted Terminal Summary"]
```

### Methodology Steps:
1. **Sanitization:** Prepend `https://` if scheme is absent, enforce hostname existence, drop URI fragments (`#section`), and disallow userinfo (`user:pass@`).
2. **Primary Probe (GET):** Dispatch a GET request using a custom user agent (`BootcampWebSecurityScanner/1.0`). Record latency, status code, and final landing URL (tracking redirects).
3. **Defensive Header Analysis:** Map observed response headers against the defined security policy table. Check conditional rules (e.g., HSTS is marked `not_applicable` over plain HTTP).
4. **CORS Probe (OPTIONS):** Dispatch an OPTIONS preflight request supplying `Origin: https://scanner-test.invalid` and preflight headers.
5. **Finding Synthesis:** Construct structured objects with `check`, `title`, `severity`, `status`, `evidence`, and `recommendation`.

---

## 7. Testing & Verification

Testing was conducted across two distinct layers:
1. **Offline Unit & Mock Response Tests** (`tests/test_scanner.py`) to verify parsing, logic branches, and error resilience without network dependencies.
2. **Local Testbed Live Probing** (`test_server.py`) against known hardened and misconfigured endpoints.

### Test Execution Matrix

| Test ID | Test Description | Target / Input | Expected Result | Actual Outcome | Status |
|---|---|---|---|---|---|
| **T01** | Automatic Scheme Addition | `example.com` | Normalizes to `https://example.com/` | `https://example.com/` | **PASS** |
| **T02** | Query Preservation & Fragment Removal | `https://example.com/page?q=1#sec` | Strips `#sec`, retains query | `https://example.com/page?q=1` | **PASS** |
| **T03** | Unsupported Protocol | `ftp://example.com` | Rejection with `ValueError` | `ValueError` raised | **PASS** |
| **T04** | Missing Hostname | `https:///` | Rejection with `ValueError` | `ValueError` raised | **PASS** |
| **T05** | Embedded Credentials | `https://user:pass@example.com` | Rejection with `ValueError` | `ValueError` raised | **PASS** |
| **T06** | Finding Structure Validation | `make_finding()` | Returns all 6 required schema keys | All 6 keys present | **PASS** |
| **T07** | Hardened Target Audit | Mocked complete headers | 0 High, 0 Medium findings | 0 High, 0 Medium | **PASS** |
| **T08** | Missing Headers Detection | Mocked empty headers on HTTPS | Flag CSP & HSTS as Medium missing | Flagged correctly | **PASS** |
| **T09** | HTTP HSTS Exemption | Mocked empty headers on HTTP | HSTS marked `not_applicable` | Marked `not_applicable` | **PASS** |
| **T10** | Dangerous CORS Detection | Wildcard (`*`) + Credentials (`true`) | Flagged as `HIGH` review finding | Flagged `HIGH` severity | **PASS** |
| **T11** | Origin Reflection Detection | Reflected `scanner-test.invalid` | Flagged as `MEDIUM` review finding | Flagged `MEDIUM` severity | **PASS** |
| **T12** | Network Outage Resilience | Mocked DNS `gaierror` | Single error finding, zero crash | Handled gracefully | **PASS** |
| **T13** | HTML Report Synthesis | Valid scan dictionary | Valid HTML5 with sanitized entities | Valid HTML rendered | **PASS** |

### Live Testbed Verification Results

#### 1. Misconfigured Local Endpoint (`http://localhost:8088/vulnerable`)
```text
Bootcamp Automated Web Security Scanner v1.0
==========================================================
Target:    http://localhost:8088/vulnerable
Status:    200
Final URL: http://localhost:8088/vulnerable
Time:      2083.81 ms
Findings:  7
----------------------------------------------------------
[MEDIUM] Content Security Policy (CSP) - missing
  Evidence: No content-security-policy header was observed in the final response.
  Advice:   Define a CSP suited to the application; begin with report-only mode if needed.
[INFO] HTTP Strict Transport Security (HSTS) - not_applicable
  Evidence: Final response URL is not HTTPS.
  Advice:   HSTS is delivered over HTTPS; configure HTTPS first, then review HSTS.
[LOW] X-Content-Type-Options - missing
  Evidence: No x-content-type-options header was observed in the final response.
  Advice:   Set X-Content-Type-Options: nosniff.
[LOW] Referrer-Policy - missing
  Evidence: No referrer-policy header was observed in the final response.
  Advice:   Set a deliberate Referrer-Policy, such as strict-origin-when-cross-origin.
[LOW] Permissions-Policy - missing
  Evidence: No permissions-policy header was observed in the final response.
  Advice:   Consider restricting browser features that the application does not need.
[MEDIUM] Framing protection - review
  Evidence: Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.
  Advice:   If the site should not be embedded by arbitrary origins, configure CSP frame-ancestors or X-Frame-Options.
[HIGH] CORS configuration - review
  Evidence: OPTIONS response included Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true.
  Advice:   Review the server's CORS implementation.
```

#### 2. Hardened Local Endpoint (`http://localhost:8088/secure`)
- Total Findings: 7
- High Severity: 0
- Medium Severity: 0
- Low Severity: 0
- Present / Compliant: All headers verified with proper policies.

---

## 8. Detailed Findings & Security Analysis

### A. Content Security Policy (CSP)
- **Finding:** `missing` (Severity: Medium)
- **Defensive Significance:** CSP restricts the domains and schemes from which scripts, stylesheets, and images can load, serving as the strongest secondary mitigation against Cross-Site Scripting (XSS) and data injection.
- **Remediation:** Implement `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';`. Initial rollouts should use `Content-Security-Policy-Report-Only` to avoid breaking production assets.

### B. HTTP Strict Transport Security (HSTS)
- **Finding:** `missing` on HTTPS (Severity: Medium) / `not_applicable` on plain HTTP (Severity: Info)
- **Defensive Significance:** Informs compliant browsers that the domain must only be reached via HTTPS, mitigating SSL-stripping man-in-the-middle attacks (e.g., Moxie Marlinspike's SSLstrip).
- **Remediation:** Configure `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` once HTTPS is verified across all subdomains.

### C. X-Content-Type-Options
- **Finding:** `missing` (Severity: Low)
- **Defensive Significance:** Instructs browsers not to sniff MIME types away from the declared `Content-Type`. This prevents malicious file uploads (e.g., an image containing executable HTML/JS) from executing in the victim's context.
- **Remediation:** Set `X-Content-Type-Options: nosniff`.

### D. Framing Protection (Clickjacking)
- **Finding:** `review` (Severity: Medium)
- **Defensive Significance:** Prevents arbitrary third-party web pages from rendering the application inside an `<iframe>`, defending against UI redressing / clickjacking attacks.
- **Remediation:** Set `X-Frame-Options: DENY` or use the modern standard `Content-Security-Policy: frame-ancestors 'none';`.

### E. Cross-Origin Resource Sharing (CORS) Misconfigurations
- **Finding:** Wildcard with Credentials / Reflected Origin (Severity: High / Medium)
- **Defensive Significance:** If an authenticated application reflects arbitrary request origins or combines `*` with credentials, unauthorized external sites can execute authenticated API requests and read private user responses.
- **Remediation:** Validate incoming `Origin` headers against an explicit server-side whitelist. Never reflect unvalidated `Origin` headers into `Access-Control-Allow-Origin`.

---

## 9. Future Enhancements

1. **Passive SSL/TLS Cipher Inspection:** Extract certificate expiration date, issuer, and negotiated TLS protocol version (e.g., alerting on deprecated TLS 1.0/1.1).
2. **Safe Multi-Route Crawling:** Support an authorized URL list or path dictionary (e.g., `/api/`, `/login`, `/dashboard`) to evaluate route-specific header variations.
3. **CI/CD Integration:** Provide exit codes reflecting severity thresholds (e.g., exit code 1 if any High findings exist) for automated pull request gating.
4. **Cookie Security Audit:** Inspect the `Set-Cookie` header for missing `Secure`, `HttpOnly`, and `SameSite` flags.

---

## 10. Conclusion

The Automated Web Security Scanner achieves its goal of delivering a reliable, dependency-free, and educational security assessment tool. By shifting security header validation into an automated, reproducible workflow, security teams can rapidly baseline web applications and identify low-hanging misconfigurations before attackers or external auditors observe them.

The addition of a local testbed (`test_server.py`), 13 automated tests, and HTML dashboard reporting transforms this utility from a basic script into a comprehensive, portfolio-ready security asset.

---

## 11. References & Standards Consulted

1. **OWASP Foundation:** *OWASP Secure Headers Project (OSHP)*, https://owasp.org/www-project-secure-headers/
2. **Mozilla Developer Network (MDN):** *HTTP Security Headers Reference*, https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
3. **PortSwigger Web Security Academy:** *Cross-Origin Resource Sharing (CORS) Vulnerabilities*, https://portswigger.net/web-security/cors
4. **RFC 6797:** *HTTP Strict Transport Security (HSTS)*, IETF, 2012.
5. **Python Software Foundation:** *Python 3 `urllib.request` and `ssl` Documentation*, https://docs.python.org/3/library/
