import unittest
from unittest.mock import patch
from scanner import normalize_url, make_finding, scan_url, generate_html_report


class URLValidationTests(unittest.TestCase):
    def test_adds_https_when_scheme_missing(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com/")

    def test_keeps_https_path_and_query(self):
        self.assertEqual(
            normalize_url("https://example.com/page?q=1#section"),
            "https://example.com/page?q=1"
        )

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            normalize_url("ftp://example.com")

    def test_rejects_missing_hostname(self):
        with self.assertRaises(ValueError):
            normalize_url("https:///")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            normalize_url("https://user:pass@example.com")


class FindingShapeTests(unittest.TestCase):
    def test_finding_contains_required_fields(self):
        item = make_finding("test", "Example", "low", "missing", "Evidence", "Advice")
        self.assertEqual(
            set(item),
            {"check", "title", "severity", "status", "evidence", "recommendation"}
        )


class MockedScannerLogicTests(unittest.TestCase):
    """Offline unit tests with mocked HTTP responses to test scan logic without network."""

    @patch("scanner.request_once")
    def test_scan_url_hardened_headers(self, mock_req):
        # 1st call is GET, 2nd call is OPTIONS
        mock_req.side_effect = [
            {
                "status_code": 200,
                "headers": {
                    "content-security-policy": "default-src 'self'",
                    "strict-transport-security": "max-age=31536000; includeSubDomains",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "strict-origin-when-cross-origin",
                    "permissions-policy": "camera=()",
                    "x-frame-options": "DENY",
                },
                "final_url": "https://example.com/",
                "elapsed_ms": 45.0,
                "error": None,
            },
            {
                "status_code": 204,
                "headers": {
                    "access-control-allow-origin": "https://trusted.example.com"
                },
                "final_url": "https://example.com/",
                "elapsed_ms": 30.0,
                "error": None,
            }
        ]

        result = scan_url("https://example.com")
        self.assertEqual(result["summary"]["by_severity"].get("high", 0), 0)
        self.assertEqual(result["summary"]["by_severity"].get("medium", 0), 0)

        # Confirm all headers are marked present
        hsts_finding = next(f for f in result["findings"] if f["check"] == "strict-transport-security")
        self.assertEqual(hsts_finding["status"], "present")

    @patch("scanner.request_once")
    def test_scan_url_missing_headers_on_https(self, mock_req):
        mock_req.side_effect = [
            {
                "status_code": 200,
                "headers": {},
                "final_url": "https://example.com/",
                "elapsed_ms": 50.0,
                "error": None,
            },
            {
                "status_code": 200,
                "headers": {},
                "final_url": "https://example.com/",
                "elapsed_ms": 30.0,
                "error": None,
            }
        ]

        result = scan_url("https://example.com")
        csp_finding = next(f for f in result["findings"] if f["check"] == "content-security-policy")
        self.assertEqual(csp_finding["status"], "missing")
        self.assertEqual(csp_finding["severity"], "medium")

        hsts_finding = next(f for f in result["findings"] if f["check"] == "strict-transport-security")
        self.assertEqual(hsts_finding["status"], "missing")
        self.assertEqual(hsts_finding["severity"], "medium")

    @patch("scanner.request_once")
    def test_hsts_skipped_on_plain_http(self, mock_req):
        mock_req.side_effect = [
            {
                "status_code": 200,
                "headers": {},
                "final_url": "http://example.com/",
                "elapsed_ms": 40.0,
                "error": None,
            },
            {
                "status_code": 200,
                "headers": {},
                "final_url": "http://example.com/",
                "elapsed_ms": 25.0,
                "error": None,
            }
        ]

        result = scan_url("http://example.com")
        hsts_finding = next(f for f in result["findings"] if f["check"] == "strict-transport-security")
        self.assertEqual(hsts_finding["status"], "not_applicable")

    @patch("scanner.request_once")
    def test_cors_wildcard_with_credentials_flagged_high(self, mock_req):
        mock_req.side_effect = [
            {
                "status_code": 200,
                "headers": {},
                "final_url": "https://example.com/",
                "elapsed_ms": 50.0,
                "error": None,
            },
            {
                "status_code": 200,
                "headers": {
                    "access-control-allow-origin": "*",
                    "access-control-allow-credentials": "true",
                },
                "final_url": "https://example.com/",
                "elapsed_ms": 35.0,
                "error": None,
            }
        ]

        result = scan_url("https://example.com")
        cors_finding = next(f for f in result["findings"] if f["check"] == "cors")
        self.assertEqual(cors_finding["severity"], "high")
        self.assertEqual(cors_finding["status"], "review")

    @patch("scanner.request_once")
    def test_cors_origin_reflection_flagged_medium(self, mock_req):
        mock_req.side_effect = [
            {
                "status_code": 200,
                "headers": {},
                "final_url": "https://example.com/",
                "elapsed_ms": 50.0,
                "error": None,
            },
            {
                "status_code": 200,
                "headers": {
                    "access-control-allow-origin": "https://scanner-test.invalid",
                },
                "final_url": "https://example.com/",
                "elapsed_ms": 35.0,
                "error": None,
            }
        ]

        result = scan_url("https://example.com")
        cors_finding = next(f for f in result["findings"] if f["check"] == "cors")
        self.assertEqual(cors_finding["severity"], "medium")
        self.assertEqual(cors_finding["status"], "review")

    @patch("scanner.request_once")
    def test_graceful_network_failure_handling(self, mock_req):
        mock_req.return_value = {
            "status_code": None,
            "headers": {},
            "final_url": "https://example.com",
            "elapsed_ms": 10.0,
            "error": "URLError: getaddrinfo failed",
        }

        result = scan_url("https://example.com")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["check"], "connection")
        self.assertEqual(result["findings"][0]["status"], "error")


class ReportGenerationTests(unittest.TestCase):
    def test_html_report_contains_target_and_findings(self):
        sample_result = {
            "scanner": "Bootcamp Automated Web Security Scanner",
            "version": "1.0",
            "scanned_at_utc": "2026-10-20T00:00:00Z",
            "target": "https://test.example.com/",
            "http": {"status_code": 200, "final_url": "https://test.example.com/", "elapsed_ms": 100},
            "findings": [
                make_finding("csp", "CSP Check", "medium", "missing", "None found", "Add CSP")
            ],
            "summary": {"total": 1, "by_severity": {"medium": 1}, "by_status": {"missing": 1}},
            "limitations": ["Educational scanner only"]
        }
        html_out = generate_html_report(sample_result)
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("https://test.example.com/", html_out)
        self.assertIn("CSP Check", html_out)
        self.assertIn("MEDIUM", html_out)


if __name__ == "__main__":
    unittest.main()
