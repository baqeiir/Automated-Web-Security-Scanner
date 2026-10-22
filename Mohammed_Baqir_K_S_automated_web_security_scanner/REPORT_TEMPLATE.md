# Project Report: Automated Web Security Scanner

**Student:** Mohammed Baqir K S  
**Bootcamp:** IBM SkillsBuild Cyber Security BootCamp 2026 — BharatCares 
**Submission date:** 23 October 2026  
**Project title:** Automated Web Security Scanner using Python

## 1. Abstract
This project implements a lightweight Python-based web security scanner that inspects selected HTTP security response headers and observes basic Cross-Origin Resource Sharing (CORS) behavior. The scanner accepts a target URL, sends HTTP requests, examines the response headers, and generates findings containing severity labels, observed evidence, and recommendations.

The project was tested against local web server endpoints configured to demonstrate different security header and CORS configurations. The provided test output shows that 13 unit tests passed. The scanner also generated JSON reports for vulnerable, secure, and CORS-reflected test scenarios.

The tool is intended for educational purposes and authorized security configuration reviews. It does not replace a comprehensive security assessment or prove that a website is completely secure.

## 2. Problem statement
Manually checking HTTP security headers can be repetitive and may lead to inconsistent documentation. Developers and students need a simple way to inspect selected security-related response headers and record configurations that may require further review.

This project addresses that need by automating a defined set of HTTP security header checks and basic CORS observations. It produces structured reports that help users understand the observed configuration and identify possible improvements.

## 3. Objectives
The main objectives of this project are:
- Accept and validate a target URL.
- Retrieve HTTP response information from an authorized target.
- Inspect selected security-related response headers.
- Observe basic CORS behavior through an OPTIONS request.
- Identify potentially missing or concerning security configurations.
- Generate findings containing evidence, severity, status, and recommendations.
- Produce machine-readable JSON reports.
- Handle common URL validation and network errors.
- Test the scanner's functionality using automated unit tests.

## 4. Scope
### Included
URL normalization and validation.
HTTP GET request handling.
HTTP response status and final URL recording.
Response time measurement.
Content-Security-Policy (CSP) checks.
HTTP Strict Transport Security (HSTS) checks.
X-Content-Type-Options checks.
Referrer-Policy checks.
Permissions-Policy checks.
Framing protection checks.
Basic CORS configuration observations.
Severity classification and remediation recommendations.
JSON and HTML report generation.
Automated unit testing and error handling.
### Excluded
The scanner does not perform:

Website crawling or comprehensive endpoint discovery.
Authentication or authorization testing.
SQL injection or other injection testing.
Exploitation of vulnerabilities.
Comprehensive application logic testing.
Full source-code security analysis.
A guarantee that a website is secure.

## 5. Tools and technologies
Programming language: Python 3.14.5, as reported by the development environment.
Python standard library: urllib, ssl, json, argparse, unittest, and html.
Development environment: Antigravity, if this is the environment used to develop and edit the project.
Operating system: Microsoft Windows 11, 64-bit.
External dependencies: No third-party Python packages are required for the scanner's standard functionality.

## 6. Methodology
The scanner follows these steps:

1. URL validation: The input URL is normalized and checked for a supported HTTP or HTTPS scheme and a valid hostname.
2. HTTP request: The scanner sends a GET request with a configured timeout.
3. Response collection: It records the HTTP status, final URL, response time, and available response headers.
4. Security header inspection: It checks selected response headers and framing protection.
5. CORS observation: It sends an OPTIONS request using a reserved test Origin to observe the server's CORS response.
6. Finding generation: It records each check's status, severity, evidence, and recommendation.
7. Report generation: It saves the findings in JSON format and can generate an HTML report.
8. Manual review: The results are interpreted in the context of the target application.

## 7. System design
The overall processing flow is:

Target URL → URL Validation → HTTP GET Request → Security Header Checks → OPTIONS/CORS Check → Findings and Severity Classification → JSON/HTML Report

Main Components

URL validation: Checks and normalizes the supplied URL before making a request.
HTTP request handling: Communicates with the target, records response information, and handles common network errors.
Security checking logic: Examines selected response headers and evaluates basic CORS behavior.
Finding generation: Creates consistent findings containing the check name, title, severity, status, evidence, and recommendation.
Report generation: Produces structured JSON output and a readable HTML report.
Unit tests: Test important behaviors such as URL validation, finding structure, CORS logic, network failure handling, and report generation.

## 8. Testing and results
Record only tests you actually performed.

| Test | Expected result | Actual result |
|---|---|---|
| Valid HTTPS URL | URL accepted | [Fill in] |
| URL without scheme | HTTPS added | [Fill in] |
| Unsupported scheme | Clear validation error | [Fill in] |
| Invalid hostname / connection failure | Error recorded without crash | [Fill in] |
| Missing security header | Finding includes recommendation | [Fill in] |
| JSON output | Report can be opened and parsed | [Fill in] |

### Target and evidence
- Authorized target: [domain or local test target; omit sensitive details]
- Scan date/time: [fill in]
- HTTP status: [fill in]
- Number of findings: [fill in]
- Screenshot 1: terminal output
- Screenshot 2: JSON report opened in editor
- Screenshot 3: test results

The project was tested using automated unit tests and a local test server.

8.1 Unit Testing

The following command was executed from the project directory:

python -m unittest discover tests -v

Actual result: 13 tests ran successfully, and the final output was OK.

The tests covered:

Required finding fields.
CORS origin reflection detection.
Wildcard CORS combined with credentials.
Network failure handling.
HSTS behavior on HTTP.
Security header scenarios.
HTML report generation.
URL normalization.
URL validation and rejection of unsupported schemes.
Handling of embedded credentials and missing hostnames.
8.2 Functional Testing

The scanner was run against three local test server endpoints on 127.0.0.1:8080.

Test scenario	Expected behavior	Observed result
Vulnerable endpoint	Identify missing headers and concerning configurations	HTTP 200; seven findings were reported
Secure endpoint	Recognize the configured security headers	HTTP 200; seven informational findings were reported
CORS-reflected endpoint	Identify reflection of the test Origin	HTTP 200; a Medium-severity CORS review finding was reported
URL validation	Accept supported URLs and reject invalid input	URL validation tests passed
Network error handling	Handle a connection failure without an uncontrolled crash	The corresponding unit test passed
HTML report generation	Produce an HTML report containing the target and findings	The corresponding unit test passed
8.3 Vulnerable Endpoint Results

Target: http://127.0.0.1:8080/vulnerable

Observed HTTP status: 200
Total findings: 7

Severity	Count
High	1
Medium	2
Low	3
Informational	1
Total	7

The scanner reported missing CSP, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy headers. It also reported missing framing protection and a CORS configuration combining a wildcard allowed origin with credential support.

The CORS result warrants configuration review, but it does not by itself prove that the endpoint is exploitable. Modern browsers reject credentialed CORS responses that use a wildcard origin.

8.4 Secure Endpoint Results

Target: http://127.0.0.1:8080/secure

Observed HTTP status: 200
Total findings: 7

All seven findings were informational. The scanner observed the selected security headers and framing protection.

HSTS was marked not applicable because the final URL used HTTP rather than HTTPS.

These results show that the expected headers were present. They do not establish that the server is completely secure or that every policy is correctly configured.

8.5 CORS-Reflected Endpoint Results

Target: http://127.0.0.1:8080/cors-reflected

Observed HTTP status: 200
Total findings: 7

The scanner reported that the server reflected the test Origin:

https://scanner-test.invalid

The CORS finding was classified as Medium severity and marked for review. Whether this behavior is a vulnerability depends on the server's origin validation, the data exposed, credential handling, and the endpoint's intended behavior.

8.6 Evidence to Include

Attach the following screenshots to your report:

Unit test results: PowerShell showing all 13 tests passing and the final OK result.
Vulnerable endpoint: The relevant JSON report showing the target and findings.
Secure endpoint: The JSON report showing the observed security headers.
CORS-reflected endpoint: The JSON report showing the reflected test Origin.
HTML report: An example generated HTML report, if available.

Use screenshots of your actual application output. Do not create simulated screenshots or present unverified results as test evidence.

## 9. Findings and discussion
For each finding, state:
- Header or check
- Observed evidence
- Why it may matter
- Recommendation
- Any context that could make it acceptable

Do not describe a missing header as a confirmed exploit without supporting evidence.

## 10. Limitations
The scanner makes only one GET and one OPTIONS request. Results are route-specific and may not represent the entire application. Header presence does not prove a secure policy. CORS is context-dependent. The scanner does not exploit vulnerabilities or test application logic.

## 11. Future improvements
- HTML report output
- Unit tests with mocked HTTP responses
- Optional local-only test server with intentionally varied headers
- Configurable header policy
- Safe multi-route checks with an explicit allowlist
- CI integration

## 12. Conclusion
Summarize what worked, what was learned, the most useful observed result, and what would be improved next.

## 13. References
List official documentation actually consulted, such as Python `urllib.request`, Python `ssl`, and OWASP guidance on HTTP security response headers and CORS.
