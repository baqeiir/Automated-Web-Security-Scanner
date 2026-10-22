#!/usr/bin/env python3
"""A small, defensive HTTP security-header and CORS configuration checker.

Use only on websites you own or have explicit permission to assess.
This tool performs a single GET request and a single CORS preflight-style OPTIONS
request. It does not exploit vulnerabilities or crawl the target.
"""
from __future__ import annotations

import argparse
import html
import json
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen


SECURITY_HEADERS = {
    "content-security-policy": {
        "title": "Content Security Policy (CSP)",
        "severity": "medium",
        "recommendation": "Define a CSP suited to the application; begin with report-only mode if needed.",
    },
    "strict-transport-security": {
        "title": "HTTP Strict Transport Security (HSTS)",
        "severity": "medium",
        "recommendation": "For HTTPS sites, configure an appropriate Strict-Transport-Security policy after confirming all subdomains support HTTPS.",
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options",
        "severity": "low",
        "recommendation": "Set X-Content-Type-Options: nosniff.",
    },
    "referrer-policy": {
        "title": "Referrer-Policy",
        "severity": "low",
        "recommendation": "Set a deliberate Referrer-Policy, such as strict-origin-when-cross-origin, based on application needs.",
    },
    "permissions-policy": {
        "title": "Permissions-Policy",
        "severity": "low",
        "recommendation": "Consider restricting browser features that the application does not need.",
    },
}

USER_AGENT = "BootcampWebSecurityScanner/1.0 (educational; single-request audit)"


def normalize_url(raw_url: str) -> str:
    """Validate a URL and add HTTPS when no scheme is provided."""
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Target URL cannot be empty.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname, e.g. https://example.com.")
    if parsed.username or parsed.password:
        raise ValueError("Do not include usernames or passwords in the URL.")
    # Drop fragments because they are not sent to the server.
    return urlunparse((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


def make_finding(check: str, title: str, severity: str, status: str,
                 evidence: str, recommendation: str) -> dict:
    return {
        "check": check,
        "title": title,
        "severity": severity,
        "status": status,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def request_once(url: str, method: str, timeout: float, origin: str | None = None):
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if origin:
        headers["Origin"] = origin
        headers["Access-Control-Request-Method"] = "GET"
        headers["Access-Control-Request-Headers"] = "content-type"
    req = Request(url, headers=headers, method=method)
    start = time.monotonic()
    try:
        # Default SSL context validates the remote TLS certificate.
        with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            elapsed = round((time.monotonic() - start) * 1000, 2)
            return {
                "status_code": response.status,
                "headers": {k.lower(): v for k, v in response.headers.items()},
                "final_url": response.geturl(),
                "elapsed_ms": elapsed,
                "error": None,
            }
    except HTTPError as exc:
        # HTTP errors still contain useful response headers/status.
        elapsed = round((time.monotonic() - start) * 1000, 2)
        return {
            "status_code": exc.code,
            "headers": {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {},
            "final_url": exc.geturl(),
            "elapsed_ms": elapsed,
            "error": None,
        }
    except (URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        elapsed = round((time.monotonic() - start) * 1000, 2)
        reason = getattr(exc, "reason", exc)
        return {
            "status_code": None,
            "headers": {},
            "final_url": url,
            "elapsed_ms": elapsed,
            "error": f"{type(reason).__name__}: {reason}",
        }


def scan_url(raw_url: str, timeout: float = 8.0) -> dict:
    target = normalize_url(raw_url)
    parsed = urlparse(target)
    # Reserved, non-real origin used only to detect risky wildcard/reflection behavior.
    test_origin = "https://scanner-test.invalid"

    main = request_once(target, "GET", timeout)
    findings = []

    if main["error"]:
        findings.append(make_finding(
            "connection", "Could not retrieve target", "info", "error",
            main["error"], "Confirm the URL, network access, DNS, and TLS certificate. Do not disable certificate validation to hide TLS errors."
        ))
        return {
            "scanner": "Bootcamp Automated Web Security Scanner",
            "version": "1.0",
            "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "http": {k: main[k] for k in ("status_code", "final_url", "elapsed_ms")},
            "findings": findings,
            "summary": {"total": 1, "by_severity": {"info": 1}, "by_status": {"error": 1}},
            "limitations": [
                "This is a lightweight configuration check, not a full penetration test.",
                "A finding is an indicator for review, not proof of exploitability.",
            ],
        }

    response_headers = main["headers"]
    is_https = urlparse(main["final_url"]).scheme.lower() == "https"

    for header, info in SECURITY_HEADERS.items():
        value = response_headers.get(header)
        if header == "strict-transport-security" and not is_https:
            findings.append(make_finding(
                header, info["title"], "info", "not_applicable",
                "Final response URL is not HTTPS.",
                "HSTS is delivered over HTTPS; configure HTTPS first, then review HSTS."
            ))
        elif value:
            findings.append(make_finding(
                header, info["title"], "info", "present",
                f"{header}: {value[:300]}",
                "Review the policy for correctness and compatibility; presence alone does not guarantee a safe configuration."
            ))
        else:
            findings.append(make_finding(
                header, info["title"], info["severity"], "missing",
                f"No {header} header was observed in the final response.",
                info["recommendation"]
            ))

    # X-Frame-Options can be replaced by a CSP frame-ancestors directive.
    xfo = response_headers.get("x-frame-options")
    csp = response_headers.get("content-security-policy", "")
    if xfo or "frame-ancestors" in csp.lower():
        findings.append(make_finding(
            "clickjacking_protection", "Framing protection", "info", "present",
            "X-Frame-Options or CSP frame-ancestors was observed.",
            "Confirm the framing policy matches the site's intended embedding behavior."
        ))
    else:
        findings.append(make_finding(
            "clickjacking_protection", "Framing protection", "medium", "review",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
            "If the site should not be embedded by arbitrary origins, configure CSP frame-ancestors or X-Frame-Options."
        ))

    # One OPTIONS request checks the server's response to a deliberately unrelated origin.
    cors = request_once(target, "OPTIONS", timeout, origin=test_origin)
    cors_headers = cors["headers"]
    allow_origin = cors_headers.get("access-control-allow-origin", "")
    allow_credentials = cors_headers.get("access-control-allow-credentials", "").lower()
    if cors["error"]:
        findings.append(make_finding(
            "cors", "CORS configuration", "info", "not_checked",
            cors["error"], "Review CORS manually; some servers do not support OPTIONS."
        ))
    elif allow_origin == "*" and allow_credentials == "true":
        findings.append(make_finding(
            "cors", "CORS configuration", "high", "review",
            "OPTIONS response included Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true.",
            "Review the server's CORS implementation. Browsers reject wildcard origins with credentialed requests, but this combination still warrants configuration review."
        ))
    elif allow_origin == "*":
        findings.append(make_finding(
            "cors", "CORS configuration", "low", "review",
            "OPTIONS response allows any origin with Access-Control-Allow-Origin: *.",
            "Wildcard access may be intentional for public resources. Confirm that sensitive responses do not rely on this policy."
        ))
    elif allow_origin == test_origin:
        findings.append(make_finding(
            "cors", "CORS configuration", "medium", "review",
            f"The server reflected the test origin: {test_origin}.",
            "Check whether origin reflection is restricted to an explicit allowlist and whether sensitive endpoints use credentials."
        ))
    elif allow_origin:
        findings.append(make_finding(
            "cors", "CORS configuration", "info", "observed",
            f"Access-Control-Allow-Origin: {allow_origin}",
            "Compare the allowed origin against the application's intended allowlist."
        ))
    else:
        findings.append(make_finding(
            "cors", "CORS configuration", "info", "no_allow_origin_observed",
            "No Access-Control-Allow-Origin header was observed on the OPTIONS response.",
            "This is not necessarily a problem. Check actual cross-origin requirements and the server's CORS behavior."
        ))

    counts_severity = {}
    counts_status = {}
    for finding in findings:
        counts_severity[finding["severity"]] = counts_severity.get(finding["severity"], 0) + 1
        counts_status[finding["status"]] = counts_status.get(finding["status"], 0) + 1

    return {
        "scanner": "Bootcamp Automated Web Security Scanner",
        "version": "1.0",
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "http": {
            "status_code": main["status_code"],
            "final_url": main["final_url"],
            "elapsed_ms": main["elapsed_ms"],
            "https": is_https,
        },
        "findings": findings,
        "summary": {
            "total": len(findings),
            "by_severity": counts_severity,
            "by_status": counts_status,
        },
        "limitations": [
            "Only one GET request and one OPTIONS request are sent; this is not a crawler.",
            "The scanner does not test authentication, authorization, application logic, injection, or exploitability.",
            "Header presence is not proof that a policy is correctly configured.",
            "CORS behavior may vary by endpoint and request; manual review is required.",
            "Run only against systems you own or have explicit permission to assess.",
        ],
    }


def generate_html_report(result: dict) -> str:
    """Generate a clean, standalone, self-contained HTML report."""
    target = html.escape(str(result.get("target", "Unknown")))
    scanned_at = html.escape(str(result.get("scanned_at_utc", "")))
    http_info = result.get("http", {})
    status_code = html.escape(str(http_info.get("status_code", "N/A")))
    final_url = html.escape(str(http_info.get("final_url", "N/A")))
    elapsed = html.escape(str(http_info.get("elapsed_ms", "N/A")))
    summary = result.get("summary", {})
    total = summary.get("total", 0)
    sev_counts = summary.get("by_severity", {})

    high_count = sev_counts.get("high", 0)
    med_count = sev_counts.get("medium", 0)
    low_count = sev_counts.get("low", 0)
    info_count = sev_counts.get("info", 0)

    findings_html_list = []
    for f in result.get("findings", []):
        sev = html.escape(f.get("severity", "info").lower())
        title = html.escape(f.get("title", ""))
        status = html.escape(f.get("status", ""))
        evidence = html.escape(f.get("evidence", ""))
        recommendation = html.escape(f.get("recommendation", ""))
        check = html.escape(f.get("check", ""))

        findings_html_list.append(f"""
        <div class="finding-card sev-{sev}">
            <div class="finding-header">
                <div>
                    <span class="badge badge-{sev}">{sev.upper()}</span>
                    <strong class="finding-title">{title}</strong>
                </div>
                <span class="badge badge-status">{status}</span>
            </div>
            <div class="finding-body">
                <p class="finding-meta"><strong>Check:</strong> <code>{check}</code></p>
                <div class="evidence-box">
                    <strong>Observed Evidence:</strong>
                    <pre><code>{evidence}</code></pre>
                </div>
                <div class="advice-box">
                    <strong>Remediation Guidance:</strong>
                    <p>{recommendation}</p>
                </div>
            </div>
        </div>""")

    findings_rendered = "\n".join(findings_html_list)

    limitations_html = "".join(
        f"<li>{html.escape(item)}</li>" for item in result.get("limitations", [])
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {target}</title>
    <style>
        :root {{
            --bg: #f8fafc;
            --surface: #ffffff;
            --text: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --high: #dc2626;
            --medium: #d97706;
            --low: #2563eb;
            --info: #475569;
            --success: #16a34a;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 960px;
            margin: 0 auto;
        }}
        header {{
            background: var(--surface);
            padding: 28px;
            border-radius: 12px;
            border: 1px solid var(--border);
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        h1 {{
            margin: 0 0 8px 0;
            font-size: 24px;
            color: #1e293b;
        }}
        .meta {{
            color: var(--text-muted);
            font-size: 14px;
            margin-bottom: 16px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            margin-top: 20px;
        }}
        .stat-card {{
            background: var(--bg);
            padding: 16px;
            border-radius: 8px;
            border: 1px solid var(--border);
            text-align: center;
        }}
        .stat-card .num {{
            font-size: 28px;
            font-weight: 700;
            display: block;
        }}
        .stat-card .label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }}
        .stat-card.stat-high .num {{ color: var(--high); }}
        .stat-card.stat-med .num {{ color: var(--medium); }}
        .stat-card.stat-low .num {{ color: var(--low); }}
        .stat-card.stat-info .num {{ color: var(--info); }}
        .stat-card.stat-total .num {{ color: var(--text); }}

        .details-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
            font-size: 14px;
        }}
        .details-table td {{
            padding: 8px 12px;
            border-bottom: 1px solid var(--border);
        }}
        .details-table td:first-child {{
            font-weight: 600;
            color: var(--text-muted);
            width: 160px;
        }}

        .section-title {{
            font-size: 20px;
            margin: 32px 0 16px 0;
            color: #1e293b;
        }}
        .finding-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            margin-bottom: 16px;
            overflow: hidden;
            border-left: 6px solid var(--info);
            box-shadow: 0 1px 2px rgba(0,0,0,0.04);
        }}
        .finding-card.sev-high {{ border-left-color: var(--high); }}
        .finding-card.sev-medium {{ border-left-color: var(--medium); }}
        .finding-card.sev-low {{ border-left-color: var(--low); }}
        .finding-card.sev-info {{ border-left-color: var(--info); }}

        .finding-header {{
            padding: 14px 20px;
            background: #fafafa;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }}
        .finding-title {{
            font-size: 16px;
            margin-left: 8px;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            font-size: 11px;
            font-weight: 700;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .badge-high {{ background: #fee2e2; color: var(--high); }}
        .badge-medium {{ background: #fef3c7; color: var(--medium); }}
        .badge-low {{ background: #dbeafe; color: var(--low); }}
        .badge-info {{ background: #e2e8f0; color: var(--info); }}
        .badge-status {{ background: #f1f5f9; color: #334155; border: 1px solid var(--border); }}

        .finding-body {{
            padding: 18px 20px;
        }}
        .finding-meta {{
            margin-top: 0;
            font-size: 13px;
            color: var(--text-muted);
        }}
        .evidence-box, .advice-box {{
            margin-top: 12px;
        }}
        .evidence-box strong, .advice-box strong {{
            font-size: 13px;
            color: #334155;
            display: block;
            margin-bottom: 4px;
        }}
        pre {{
            background: #f1f5f9;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 13px;
            margin: 4px 0 0 0;
            border: 1px solid #e2e8f0;
        }}
        code {{
            font-family: Consolas, Monaco, "Courier New", monospace;
        }}
        .advice-box {{
            background: #f8fafc;
            border-left: 3px solid #0284c7;
            padding: 10px 14px;
            border-radius: 0 6px 6px 0;
        }}
        .advice-box p {{
            margin: 0;
            font-size: 13px;
            color: #0f172a;
        }}

        footer {{
            margin-top: 40px;
            padding: 20px;
            background: var(--surface);
            border-radius: 8px;
            border: 1px solid var(--border);
            font-size: 13px;
            color: var(--text-muted);
        }}
        footer ul {{
            margin: 8px 0 0 20px;
            padding: 0;
        }}
        footer li {{
            margin-bottom: 4px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Scan Report</h1>
            <div class="meta">Automated Web Security Scanner v1.0 &bull; Scanned at (UTC): {scanned_at}</div>
            <table class="details-table">
                <tr><td>Target</td><td><code>{target}</code></td></tr>
                <tr><td>Final URL</td><td><code>{final_url}</code></td></tr>
                <tr><td>HTTP Status</td><td><code>{status_code}</code></td></tr>
                <tr><td>Response Time</td><td>{elapsed} ms</td></tr>
            </table>

            <div class="grid">
                <div class="stat-card stat-total">
                    <span class="num">{total}</span>
                    <span class="label">Total Findings</span>
                </div>
                <div class="stat-card stat-high">
                    <span class="num">{high_count}</span>
                    <span class="label">High</span>
                </div>
                <div class="stat-card stat-med">
                    <span class="num">{med_count}</span>
                    <span class="label">Medium</span>
                </div>
                <div class="stat-card stat-low">
                    <span class="num">{low_count}</span>
                    <span class="label">Low</span>
                </div>
                <div class="stat-card stat-info">
                    <span class="num">{info_count}</span>
                    <span class="label">Info / Present</span>
                </div>
            </div>
        </header>

        <h2 class="section-title">Inspection Findings & Recommendations</h2>
        {findings_rendered}

        <footer>
            <strong>Scope & Limitations:</strong>
            <ul>
                {limitations_html}
            </ul>
        </footer>
    </div>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Lightweight HTTP security-header and CORS checker (authorized targets only)."
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds (default: 8)")
    parser.add_argument("--output", default="report.json", help="JSON report path (default: report.json)")
    parser.add_argument("--html", default=None, help="Optional HTML report path (e.g. report.html)")
    args = parser.parse_args()

    if args.timeout <= 0 or args.timeout > 30:
        parser.error("--timeout must be greater than 0 and no more than 30 seconds")

    try:
        result = scan_url(args.url, args.timeout)
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    output_path = args.output
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False)

    if args.html:
        html_content = generate_html_report(result)
        with open(args.html, "w", encoding="utf-8") as handle:
            handle.write(html_content)

    print(f"\n{result['scanner']} v{result['version']}")
    print("=" * 58)
    print(f"Target:    {result['target']}")
    print(f"Status:    {result['http']['status_code']}")
    print(f"Final URL: {result['http']['final_url']}")
    print(f"Time:      {result['http'].get('elapsed_ms', 'N/A')} ms")
    print(f"Findings:  {len(result['findings'])}")
    print("-" * 58)
    for finding in result["findings"]:
        print(f"[{finding['severity'].upper()}] {finding['title']} - {finding['status']}")
        print(f"  Evidence: {finding['evidence']}")
        print(f"  Advice:   {finding['recommendation']}")
    print(f"\nJSON report saved to: {output_path}")
    if args.html:
        print(f"HTML report saved to: {args.html}")
    print("\nReminder: findings are indicators, not proof of exploitability.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
