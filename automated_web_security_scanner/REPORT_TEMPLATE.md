# Project Report: Automated Web Security Scanner

**Student:** Mohammed Baqir K S  
**Bootcamp:** BharatCares Cybersecurity Bootcamp 
**Submission date:** 23 October 2026  
**Project title:** Automated Web Security Scanner using Python

## 1. Abstract
This project implements a lightweight Python tool to inspect HTTP security headers and observe basic CORS behavior. It creates a JSON report containing evidence, severity labels, and recommendations. The tool is intended for authorized, educational configuration reviews.

## 2. Problem statement
Manually checking basic web security headers can be repetitive. A small automated checker can make initial configuration reviews more consistent and produce reusable evidence for review.

## 3. Objectives
- Retrieve an HTTP response from an authorized target.
- Check selected security-related response headers.
- Observe basic CORS behavior through an OPTIONS request.
- Produce structured findings with remediation suggestions.
- Handle common input and connection errors safely.

## 4. Scope
### Included
Security headers, basic CORS observation, response status, final URL, elapsed time, JSON output.

### Excluded
Exploitation, crawling, authentication testing, authorization testing, injection testing, source-code review, and certification that a site is secure.

## 5. Tools and technologies
- Python Python 3.14.5
- Python standard library: `urllib`, `ssl`, `json`, `argparse`, `unittest`
- Editor: [VS Code / other]
- Operating system: [Windows 11 / macOS / Linux]

## 6. Methodology
1. Validate and normalize the URL.
2. Send one GET request with a timeout and normal TLS certificate validation.
3. Inspect the final response headers.
4. Send one OPTIONS request with a reserved test Origin to observe CORS behavior.
5. Create findings with status, severity, evidence, and recommendations.
6. Save the output as JSON and review the results manually.

## 7. System design
[Insert a simple flow diagram: Target URL → URL validation → GET request → header checks → OPTIONS/CORS check → findings → JSON report.]

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
