# 3-Minute Demonstration Script & Evaluator Q&A Guide

**Project:** Automated Web Security Scanner (Python)  
**Presenter:** Mohammed Baqir K S 
**Audience:** BharatCares Cybersecurity Bootcamp Evaluators / Technical Interviewers  
**Target Duration:** ~3 minutes (Demo: 2 mins, Q&A: 1 min)

---

## 1. Demonstration Setup (Before Presenting)

Have two PowerShell windows open side-by-side:
- **Left Window:** Navigated to the project folder, ready to run `python test_server.py --port 8080`.
- **Right Window:** Navigated to the project folder, ready to run the tests and scanner.
- **Browser Window:** Minimized, ready to open `report_vuln.html` and `report_secure.html`.

---

## 2. 3-Minute Presentation Script

### Minute 0:00 - 0:45 | Introduction & Problem Context
> *"Good morning/afternoon, evaluators. My name is Baqir, and today I'm demonstrating my Cybersecurity Bootcamp Final Project: the **Automated Web Security Scanner**.*
>
> *In web security, developers often focus heavily on server-side logic while neglecting HTTP defense-in-depth mechanisms—such as Content Security Policy, HSTS, and CORS controls. Omitting these headers leaves websites vulnerable to Clickjacking, XSS exploitation, MIME-confusion attacks, and unauthorized cross-origin data exposure.*
>
> *I designed this tool to solve that problem: a lightweight, non-exploitative security auditor built purely in Python's standard library. It requires zero third-party dependencies, runs offline or online, and delivers structured findings in both JSON and an executive HTML dashboard."*

---

### Minute 0:45 - 1:30 | Technical Architecture & Offline Unit Testing
> *(Switch to Right Terminal)*
>
> *"Before scanning any live target, reliability and defensive safety are paramount. I wrote a suite of 13 automated unit tests using `unittest` and `unittest.mock`."*
>
> *(Run command in terminal)*:
> ```powershell
> python -m unittest discover tests
> ```
>
> *"Notice that all 13 tests pass in under 5 milliseconds. These tests verify input sanitization, URL normalization, network failure resilience, and mock HTTP responses for both hardened and misconfigured endpoints without generating live traffic."*

---

### Minute 1:30 - 2:30 | Live Simulation & Finding Walkthrough
> *(Switch to Left Terminal and start test server)*:
> ```powershell
> python test_server.py --port 8080
> ```
>
> *"To ensure safe and reproducible testing without unauthorized external scanning, I built a local mock HTTP server that simulates real-world vulnerable and hardened endpoints.*
>
> *(Switch to Right Terminal and run scanner against vulnerable endpoint)*:
> ```powershell
> python scanner.py http://localhost:8080/vulnerable --output report.json --html report.html
> ```
>
> *"The scanner dispatches two carefully designed requests: a GET request to audit response headers, and an RFC-compliant preflight OPTIONS request with a non-routable origin (`https://scanner-test.invalid`) to probe CORS behavior.*
>
> *(Point to terminal output)*:
> - *Notice it flagged a **HIGH** finding on CORS: the server paired a wildcard origin `*` with credentials `true`.*
> - *It identified **MEDIUM** findings for missing Content Security Policy and absent Framing Protection.*
> - *Crucially, notice how it handled HSTS: because this target was on HTTP, HSTS was marked `not_applicable` rather than generating a false positive, since browsers only enforce HSTS over HTTPS."*
>
> *(Open `report.html` in browser)*:
>
> *"The tool also generated this standalone HTML executive dashboard, showing severity distributions, recorded evidence, and OWASP-aligned remediation advice."*

---

### Minute 2:30 - 3:00 | Limitations & Conclusion
> *"To conclude, an important ethical and technical principle: a missing security header or wildcard CORS policy is an indicator for review, not automatic proof of an exploitable breach. A public API, for instance, may legitimately use wildcard CORS.*
>
> *In future iterations, I plan to add passive TLS cipher suite inspection and multi-route path scanning. Thank you, and I welcome any questions."*

---

## 3. Evaluator Q&A Sheet (Common Doubts)

### Q1: Why did you use Python's standard library (`urllib`) instead of the popular `requests` library?
**Baqir's Answer:**  
> *"I deliberately chose Python's standard library to guarantee portability, zero supply-chain risk, and immediate cross-platform execution. Any security analyst or automated server can pull this script and run it immediately on Windows, Linux, or macOS without needing `pip`, virtual environments, or external dependencies. It also gave me a deeper understanding of low-level HTTP protocols, SSL contexts, and urllib error handling."*

### Q2: Why is a missing Content Security Policy (CSP) ranked as 'Medium' instead of 'Critical'?
**Baqir's Answer:**  
> *"CSP is a secondary defensive mitigation, not the root vulnerability itself. If an application has zero XSS vulnerabilities, the absence of CSP causes no direct exploitability. CSP is defense-in-depth: it stops an attacker from executing injected scripts if a primary XSS vulnerability exists. Marking it Critical would be a false positive; Medium accurately reflects its risk as a missing defense layer."*

### Q3: What is the risk of having `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`?
**Baqir's Answer:**  
> *"Under the W3C CORS specification, modern web browsers will actually block front-end JavaScript from reading a response that combines `*` with `credentials: true`. However, when a backend server sends this combination, it indicates severe misconfiguration—often that the backend developer intended to allow authenticated cross-origin requests without understanding how CORS security controls operate. That's why the scanner flags it as a High-priority configuration review."*

### Q4: How does your scanner handle TLS certificate errors and malicious targets?
**Baqir's Answer:**  
> *"The scanner explicitly uses `ssl.create_default_context()`, which enforces strict X.509 certificate chain validation and hostname verification. It never disables SSL verification (`verify=False`). If a target has an expired or self-signed certificate, the exception is caught safely in `request_once`, documented as an evidence finding in the JSON/HTML report, and the program continues without crashing."*

### Q5: How did you test your scanner without scanning websites you don't own?
**Baqir's Answer:**  
> *"Ethical compliance is essential in cybersecurity. I used two independent methods: first, an offline test suite using `unittest.mock` to simulate HTTP responses in memory; second, I engineered a zero-dependency local mock server (`test_server.py`) that serves hardened, vulnerable, and reflected CORS endpoints directly on localhost. This gave me 100% reproducible test evidence without touching external third-party infrastructure."*
