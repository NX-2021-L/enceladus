"""Offline tests for elr_list.py (ENC-TSK-Q16 / plan ENC-PLN-093 objective
O4). No network access -- urlopen is mocked via unittest.mock.patch,
matching elr_batch_get.py's/elr_sync.py's test style.

ENC-TSK-Q16-0A: parser skeleton (--project/--type/--status/--page-size),
the --project '_' sentinel rejection, and the base plain-list route.
--census (0B), --page/--pages (0C), and the capability preflight (0D)
extend this file in later commits.
"""

from __future__ import annotations

import contextlib
import io
import json
import unittest
import urllib.error
from unittest.mock import patch

import elr_list

_URLOPEN = "elr_lib.transport.urllib.request.urlopen"

_STABLE_KEYS = {"operation", "ok", "status", "identity_posture", "anomalies"}


class _FakeHttpResponse:
    def __init__(self, status, body):
        self._status = status
        self._body = body

    def getcode(self):
        return self._status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _ok(body):
    return _FakeHttpResponse(200, json.dumps(body).encode("utf-8"))


def _http_error(code, body=b""):
    return urllib.error.HTTPError(
        url="https://jreese.net/api/v1/tracker",
        code=code,
        msg="error",
        hdrs=None,
        fp=io.BytesIO(body),
    )


class AllowAbbrevAndHelpTests(unittest.TestCase):
    def test_parser_has_allow_abbrev_false(self):
        parser = elr_list.build_parser()
        self.assertFalse(parser.allow_abbrev)

    def test_help_renders_with_expected_flags(self):
        parser = elr_list.build_parser()
        stdout = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stdout(stdout):
                parser.parse_args(["--help"])
        self.assertEqual(ctx.exception.code, 0)
        rendered = stdout.getvalue()
        for flag in ("--project", "--type", "--status", "--page-size"):
            self.assertIn(flag, rendered)

    def test_default_page_size_is_100(self):
        parser = elr_list.build_parser()
        args = parser.parse_args(["--project", "enceladus"])
        self.assertEqual(args.page_size, 100)


class ProjectSentinelRejectionTests(unittest.TestCase):
    def test_project_underscore_rejected_by_argparse(self):
        parser = elr_list.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(stderr):
                parser.parse_args(["--project", "_"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("not a valid project id", stderr.getvalue())

    def test_project_underscore_issues_no_request(self):
        # main() itself must never reach the network when argparse refuses
        # the args -- parser.parse_args() raises before any client exists.
        with patch(_URLOPEN) as mock_urlopen:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    elr_list.main(["--project", "_"])
        mock_urlopen.assert_not_called()

    def test_ordinary_project_id_accepted(self):
        parser = elr_list.build_parser()
        args = parser.parse_args(["--project", "enceladus"])
        self.assertEqual(args.project, "enceladus")


class PageSizeBoundsTests(unittest.TestCase):
    def test_page_size_over_max_rejected(self):
        parser = elr_list.build_parser()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["--project", "p", "--page-size", "201"])
        self.assertEqual(ctx.exception.code, 2)

    def test_page_size_max_accepted(self):
        parser = elr_list.build_parser()
        args = parser.parse_args(["--project", "p", "--page-size", "200"])
        self.assertEqual(args.page_size, 200)

    def test_page_size_zero_rejected(self):
        parser = elr_list.build_parser()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["--project", "p", "--page-size", "0"])
        self.assertEqual(ctx.exception.code, 2)


class PlainListRouteTests(unittest.TestCase):
    def test_plain_list_calls_tracker_route_with_query_params_only(self):
        body = {"success": True, "records": [{"record_id": "ENC-TSK-1"}, {"record_id": "ENC-TSK-2"}], "count": 2, "page_size": 100}
        with patch(_URLOPEN, side_effect=[_ok(body)]) as mock_urlopen:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = elr_list.main(["--project", "enceladus", "--type", "task", "--status", "open"])
        self.assertEqual(exit_code, 0)
        self.assertEqual(mock_urlopen.call_count, 1)
        request = mock_urlopen.call_args[0][0]
        self.assertIn("/enceladus", request.full_url)
        self.assertIn("type=task", request.full_url)
        self.assertIn("status=open", request.full_url)
        digest = json.loads(stdout.getvalue().strip())
        self.assertTrue(digest["ok"])
        self.assertEqual(digest["counts"], {"records": 2})

    def test_plain_list_server_error_reported(self):
        with patch(_URLOPEN, side_effect=[_http_error(500, json.dumps({"error": "boom"}).encode())]):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = elr_list.main(["--project", "enceladus"])
        self.assertEqual(exit_code, 1)
        digest = json.loads(stdout.getvalue().strip())
        self.assertFalse(digest["ok"])


if __name__ == "__main__":
    unittest.main()
