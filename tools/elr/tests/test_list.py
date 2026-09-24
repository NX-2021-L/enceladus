"""Offline tests for elr_list.py (ENC-TSK-Q16 / plan ENC-PLN-093 objective
O4). No network access -- urlopen is mocked via unittest.mock.patch,
matching elr_batch_get.py's/elr_sync.py's test style.

ENC-TSK-Q16-0A: parser skeleton (--project/--type/--status/--page-size),
the --project '_' sentinel rejection, and the base plain-list route.
ENC-TSK-Q16-0B adds --census's digest-exact-keys and side-file contract.
--page/--pages (0C) and the capability preflight (0D) extend this file
in later commits.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
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


class CensusModeTests(unittest.TestCase):
    def _census_body(self):
        return {
            "count": 70,
            "count_truncated": False,
            "exhausted": True,
            "pages": [
                {"cursor": None, "first": {"id": "ENC-TSK-1", "status": "open", "title": "t1"}, "last": {"id": "ENC-TSK-50", "status": "open", "title": "t50"}, "n": 50},
                {"cursor": "CURSOR-1", "first": {"id": "ENC-TSK-51", "status": "open", "title": "t51"}, "last": {"id": "ENC-TSK-70", "status": "open", "title": "t70"}, "n": 20},
            ],
            "page_size": 50,
            "as_of": {"kind": "wall_clock+max_updated_at", "started_at": "2026-09-24T05:00:00Z", "max_updated_at": "2026-09-24T05:00:01Z"},
            "order": "record_id_asc",
            "by_type": {"task": 70, "issue": 0, "feature": 0, "plan": 0, "lesson": 0, "escalation": 0},
            "ids_inline_cap": 500,
        }

    def test_census_digest_keys_exactly_the_six(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch(_URLOPEN, side_effect=[_ok(self._census_body())]):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = elr_list.main(["--project", "enceladus", "--lists-dir", tmp, "--census"])
        self.assertEqual(exit_code, 0)
        digest = json.loads(stdout.getvalue().strip())
        optional_keys = set(digest.keys()) - _STABLE_KEYS
        self.assertEqual(optional_keys, {"count", "exhausted", "count_truncated", "pages", "as_of", "by_type"})
        self.assertEqual(digest["count"], 70)
        self.assertEqual(digest["exhausted"], True)
        self.assertEqual(digest["count_truncated"], False)
        self.assertEqual(len(digest["pages"]), 2)
        self.assertEqual(digest["by_type"]["task"], 70)

    def test_census_writes_verbatim_side_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = self._census_body()
            with patch(_URLOPEN, side_effect=[_ok(body)]):
                with contextlib.redirect_stdout(io.StringIO()):
                    exit_code = elr_list.main(
                        ["--project", "enceladus", "--type", "task", "--status", "open", "--lists-dir", tmp, "--census"]
                    )
            self.assertEqual(exit_code, 0)
            expected_path = Path(tmp) / "enceladus_task_open_2026-09-24T05:00:00Z.census.json"
            self.assertTrue(expected_path.is_file())
            on_disk = json.loads(expected_path.read_text(encoding="utf-8"))
            self.assertEqual(on_disk, body)

    def test_census_file_uses_all_when_no_type_or_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch(_URLOPEN, side_effect=[_ok(self._census_body())]):
                with contextlib.redirect_stdout(io.StringIO()):
                    exit_code = elr_list.main(["--project", "enceladus", "--lists-dir", tmp, "--census"])
            self.assertEqual(exit_code, 0)
            expected_path = Path(tmp) / "enceladus_all_all_2026-09-24T05:00:00Z.census.json"
            self.assertTrue(expected_path.is_file())

    def test_census_server_error_reported_not_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch(_URLOPEN, side_effect=[_http_error(500, json.dumps({"error": "boom"}).encode())]):
                with contextlib.redirect_stdout(io.StringIO()):
                    exit_code = elr_list.main(["--project", "enceladus", "--lists-dir", tmp, "--census"])
            self.assertEqual(exit_code, 1)
            self.assertEqual(list(Path(tmp).glob("*.census.json")), [])


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
