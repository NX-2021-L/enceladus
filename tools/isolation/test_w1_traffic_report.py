"""DVP-TSK-A96: parsing and grouping for the isolation W1 traffic report (no AWS)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import w1_traffic_report as w  # noqa: E402

CF = [
    "#Version: 1.0",
    "#Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status cs(Referer) cs(User-Agent)",
    "2026-10-12\t14:00:00\tSFO5\t512\t198.51.100.7\tGET\td1.cloudfront.net\t/api/v1/tracker/x\t200\t-\tcurl/8.0",
    "2026-10-12\t14:00:01\tSFO5\t512\t198.51.100.8\tGET\td1.cloudfront.net\t/.well-known/oauth-authorization-server\t200\t-\tclaude",
    "2026-10-12\t14:00:02\tSFO5\t512\t198.51.100.9\tGET\td1.cloudfront.net\t/index.html\t200\t-\tMozilla",
]
S3 = ('79a5 jreese-net [12/Oct/2026:14:00:00 +0000] 198.51.100.7 arn:aws:sts::1:assumed-role/feed/x REQ1 REST.GET.OBJECT '
      'agent-documents/a/b.md "GET /agent-documents/a/b.md HTTP/1.1" 200 - 10 10 5 4 "-" "Boto3/1.0" - HOST SigV4 '
      'ECDHE TLSv1.3 - -')


class TestParsing(unittest.TestCase):
    def test_cloudfront_rows_and_families(self):
        rows = list(w.parse_cloudfront(CF))
        self.assertEqual(len(rows), 3)
        self.assertEqual(w.path_family(rows[0]["cs-uri-stem"]), "/api/v1/tracker")
        self.assertEqual(w.path_family(rows[1]["cs-uri-stem"]), "/.well-known/oauth-*")
        self.assertIsNone(w.path_family(rows[2]["cs-uri-stem"]))

    def test_s3_access_line(self):
        r = w.parse_s3_access(S3)
        self.assertEqual(r["requester"], "arn:aws:sts::1:assumed-role/feed/x")
        self.assertEqual(r["operation"], "REST.GET.OBJECT")
        self.assertEqual(r["key"], "agent-documents/a/b.md")
        self.assertEqual(r["status"], "200")
        self.assertEqual(r["ua"], "Boto3/1.0")
        self.assertEqual(w.s3_family(r["key"]), "agent-documents/")
        self.assertEqual(w.s3_family("gamma/governance/x"), "gamma/governance/")
        self.assertIsNone(w.s3_family("index.html"))

    def test_report_counts_without_printing_ips(self):
        text = w.report(w.parse_cloudfront(CF), [w.parse_s3_access(S3)], 7)
        self.assertIn("Enceladus-path requests: 2", text)
        self.assertIn("`/api/v1/tracker` status 200: 1 requests", text)
        self.assertIn("`agent-documents/` REST.GET.OBJECT by arn:aws:sts::1:assumed-role/feed/x: 1", text)
        self.assertNotIn("198.51.100", text)

    def test_empty_window_says_none(self):
        text = w.report([], [], 7)
        self.assertEqual(text.count("None in the window."), 2)


if __name__ == "__main__":
    unittest.main()
