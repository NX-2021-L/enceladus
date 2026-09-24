"""Offline tests for elr_list.py (ENC-TSK-Q16 / plan ENC-PLN-093 objective
O4). No network access -- urlopen is mocked via unittest.mock.patch,
matching elr_batch_get.py's/elr_sync.py's test style.

ENC-TSK-Q16-0A: parser skeleton (--project/--type/--status/--page-size)
and the --project '_' sentinel rejection.
ENC-TSK-Q16-0B: --census's digest-exact-keys and side-file contract.
ENC-TSK-Q16-0C: --page (single raw page, ids-file loadable by
elr_batch_get.py --ids-file) and --pages N (a bounded loop over a prior
--census side file's page-boundary cursors).
ENC-TSK-Q16-0D: the tracker_capabilities.census preflight -- every mode
test below now runs through _run_main(), which prepends the health
check's mocked response automatically.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest.mock import patch

import elr_batch_get
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


_HEALTH_CENSUS_TRUE = _ok({"tracker_capabilities": {"census": True, "list_cursor_v2": True}, "governance_hash": "gh1"})
_HEALTH_CENSUS_FALSE = _ok({"tracker_capabilities": {"census": False, "list_cursor_v2": True}})
_HEALTH_CENSUS_ABSENT = _ok({})


def _records(ids):
    return [{"record_id": rid, "record_type": "task", "status": "open", "title": rid} for rid in ids]


def _run_main(argv, responses):
    """Runs elr_list.main(), with the tracker_capabilities.census preflight
    call (ENC-TSK-Q16-0D) prepended to `responses` -- callers supply only
    the mode's own response(s)."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    with patch(_URLOPEN, side_effect=[_HEALTH_CENSUS_TRUE, *responses]) as mock_urlopen:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = elr_list.main(argv)
    lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
    digest = json.loads(lines[-1]) if lines else None
    return exit_code, digest, mock_urlopen, stderr.getvalue()


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
        for flag in ("--project", "--type", "--status", "--page-size", "--census", "--page", "--pages"):
            self.assertIn(flag, rendered)

    def test_default_page_size_is_100(self):
        parser = elr_list.build_parser()
        args = parser.parse_args(["--project", "enceladus", "--census"])
        self.assertEqual(args.page_size, 100)


class ProjectSentinelRejectionTests(unittest.TestCase):
    def test_project_underscore_rejected_by_argparse(self):
        parser = elr_list.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(stderr):
                parser.parse_args(["--project", "_", "--census"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("not a valid project id", stderr.getvalue())

    def test_project_underscore_issues_no_request(self):
        # main() itself must never reach the network when argparse refuses
        # the args -- parser.parse_args() raises before any client exists.
        with patch(_URLOPEN) as mock_urlopen:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    elr_list.main(["--project", "_", "--census"])
        mock_urlopen.assert_not_called()

    def test_ordinary_project_id_accepted(self):
        parser = elr_list.build_parser()
        args = parser.parse_args(["--project", "enceladus", "--census"])
        self.assertEqual(args.project, "enceladus")


class PageSizeAndPagesBoundsTests(unittest.TestCase):
    def test_page_size_over_max_rejected(self):
        parser = elr_list.build_parser()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["--project", "p", "--page-size", "201", "--census"])
        self.assertEqual(ctx.exception.code, 2)

    def test_page_size_max_accepted(self):
        parser = elr_list.build_parser()
        args = parser.parse_args(["--project", "p", "--page-size", "200", "--census"])
        self.assertEqual(args.page_size, 200)

    def test_page_size_zero_rejected(self):
        parser = elr_list.build_parser()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["--project", "p", "--page-size", "0", "--census"])
        self.assertEqual(ctx.exception.code, 2)

    def test_pages_eleven_rejected(self):
        parser = elr_list.build_parser()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["--project", "p", "--pages", "11"])
        self.assertEqual(ctx.exception.code, 2)

    def test_pages_ten_accepted(self):
        parser = elr_list.build_parser()
        args = parser.parse_args(["--project", "p", "--pages", "10"])
        self.assertEqual(args.pages, 10)

    def test_all_flag_is_not_recognized(self):
        # No --all anywhere in this CLI -- argparse rejects it outright.
        parser = elr_list.build_parser()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["--project", "p", "--all"])
        self.assertEqual(ctx.exception.code, 2)

    def test_census_and_page_are_mutually_exclusive(self):
        parser = elr_list.build_parser()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["--project", "p", "--census", "--page", "X"])
        self.assertEqual(ctx.exception.code, 2)

    def test_no_mode_flag_errors(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch(_URLOPEN) as mock_urlopen:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as ctx:
                    elr_list.main(["--project", "enceladus"])
        self.assertEqual(ctx.exception.code, 2)
        mock_urlopen.assert_not_called()


class CapabilityPreflightTests(unittest.TestCase):
    def test_capability_absent_exits_6_with_zero_list_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch(_URLOPEN, side_effect=[_HEALTH_CENSUS_ABSENT]) as mock_urlopen:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = elr_list.main(["--project", "enceladus", "--lists-dir", tmp, "--census"])
        self.assertEqual(exit_code, elr_list.EXIT_CENSUS_UNSUPPORTED)
        self.assertEqual(mock_urlopen.call_count, 1)  # only the health call
        self.assertIn(elr_list.CENSUS_UNSUPPORTED_MESSAGE, stderr.getvalue())
        digest = json.loads(stdout.getvalue().strip())
        self.assertFalse(digest["ok"])
        self.assertIn(elr_list.CENSUS_UNSUPPORTED_MESSAGE, digest["anomalies"])

    def test_capability_false_exits_6_with_zero_list_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with patch(_URLOPEN, side_effect=[_HEALTH_CENSUS_FALSE]) as mock_urlopen:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                    exit_code = elr_list.main(["--project", "enceladus", "--lists-dir", tmp, "--page", "somecursor"])
        self.assertEqual(exit_code, elr_list.EXIT_CENSUS_UNSUPPORTED)
        self.assertEqual(mock_urlopen.call_count, 1)

    def test_capability_true_proceeds_to_census_request(self):
        census_body = {
            "count": 0,
            "count_truncated": False,
            "exhausted": True,
            "pages": [],
            "page_size": 100,
            "as_of": {"kind": "wall_clock+max_updated_at", "started_at": "2026-09-24T05:00:00Z", "max_updated_at": None},
            "order": "record_id_asc",
            "by_type": {"task": 0, "issue": 0, "feature": 0, "plan": 0, "lesson": 0, "escalation": 0},
            "ids_inline_cap": 500,
        }
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, digest, mock_urlopen, _stderr = _run_main(
                ["--project", "enceladus", "--lists-dir", tmp, "--census"],
                [_ok(census_body)],
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(mock_urlopen.call_count, 2)
        self.assertTrue(digest["ok"])

    def test_exit_code_documented_in_docs_section(self):
        docs = (Path(__file__).resolve().parent.parent / "docs" / "ELR_V2_SECTION.md").read_text(encoding="utf-8")
        self.assertIn("CENSUS_UNSUPPORTED", docs)
        self.assertIn("elr_list", docs)


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
            exit_code, digest, _mock, _stderr = _run_main(
                ["--project", "enceladus", "--lists-dir", tmp, "--census"],
                [_ok(self._census_body())],
            )
        self.assertEqual(exit_code, 0)
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
            exit_code, _digest, _mock, _stderr = _run_main(
                ["--project", "enceladus", "--type", "task", "--status", "open", "--lists-dir", tmp, "--census"],
                [_ok(body)],
            )
            self.assertEqual(exit_code, 0)
            expected_path = Path(tmp) / "enceladus_task_open_2026-09-24T05:00:00Z.census.json"
            self.assertTrue(expected_path.is_file())
            on_disk = json.loads(expected_path.read_text(encoding="utf-8"))
            self.assertEqual(on_disk, body)

    def test_census_file_uses_all_when_no_type_or_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, _digest, _mock, _stderr = _run_main(
                ["--project", "enceladus", "--lists-dir", tmp, "--census"],
                [_ok(self._census_body())],
            )
            self.assertEqual(exit_code, 0)
            expected_path = Path(tmp) / "enceladus_all_all_2026-09-24T05:00:00Z.census.json"
            self.assertTrue(expected_path.is_file())

    def test_census_server_error_reported_not_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, digest, _mock, _stderr = _run_main(
                ["--project", "enceladus", "--lists-dir", tmp, "--census"],
                [_http_error(500, json.dumps({"error": "boom"}).encode())],
            )
            self.assertEqual(exit_code, 1)
            self.assertFalse(digest["ok"])
            self.assertEqual(list(Path(tmp).glob("*.census.json")), [])

    def test_census_request_sends_mode_census_and_filters(self):
        """The AC-mandated request contract for --census: the outgoing GET
        must actually carry mode=census (plus the type/status/page_size
        filters), not just parse a census-shaped response -- a regression
        that dropped mode=census from the query dict would still pass
        every other test in this class."""
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, _digest, mock_urlopen, _stderr = _run_main(
                ["--project", "enceladus", "--type", "task", "--status", "open", "--lists-dir", tmp, "--census"],
                [_ok(self._census_body())],
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(mock_urlopen.call_count, 2)  # health + the census request
            req = mock_urlopen.call_args_list[1][0][0]
            parts = urllib.parse.urlsplit(req.full_url)
            self.assertEqual(parts.path, "/api/v1/tracker/enceladus")
            query = urllib.parse.parse_qs(parts.query)
            self.assertEqual(query["mode"], ["census"])
            self.assertEqual(query["type"], ["task"])
            self.assertEqual(query["status"], ["open"])
            self.assertEqual(query["page_size"], ["100"])
            self.assertNotIn("next_cursor", query)


class PageModeTests(unittest.TestCase):
    def test_single_page_writes_ids_file_loadable_by_batch_get(self):
        ids = [f"ENC-TSK-{i}" for i in range(51, 71)]
        page_body = {"success": True, "records": _records(ids), "count": len(ids), "page_size": 50}
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, digest, mock_urlopen, _stderr = _run_main(
                ["--project", "enceladus", "--lists-dir", tmp, "--page", "CURSOR-1"],
                [_ok(page_body)],
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(mock_urlopen.call_count, 2)  # health + the one page fetch
            optional_keys = set(digest.keys()) - _STABLE_KEYS
            self.assertEqual(optional_keys, {"n"})  # no next_cursor -> page_truncated/next_cursor omitted
            self.assertEqual(digest["n"], 20)

            expected_hash = hashlib.sha256(b"CURSOR-1").hexdigest()[:12]
            ids_path = Path(tmp) / f"enceladus_{expected_hash}.ids"
            self.assertTrue(ids_path.is_file())
            loaded = elr_batch_get.load_ids_file(str(ids_path))
            self.assertEqual(loaded, ids)

    def test_page_with_next_cursor_reports_page_truncated(self):
        page_body = {
            "success": True,
            "records": _records(["ENC-TSK-1"]),
            "count": 1,
            "page_size": 50,
            "next_cursor": "CURSOR-2",
        }
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, digest, _mock, _stderr = _run_main(
                ["--project", "enceladus", "--lists-dir", tmp, "--page", "CURSOR-1"],
                [_ok(page_body)],
            )
        self.assertEqual(exit_code, 0)
        self.assertTrue(digest["page_truncated"])
        self.assertEqual(digest["next_cursor"], "CURSOR-2")

    def test_page_start_cursor_is_none(self):
        # The first census page anchor has cursor=None -- --page must accept
        # that as "start of the walk" and still produce a stable file name.
        page_body = {"success": True, "records": _records(["ENC-TSK-1"]), "count": 1, "page_size": 50}
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, _digest, _mock, _stderr = _run_main(
                ["--project", "enceladus", "--lists-dir", tmp, "--page", ""],
                [_ok(page_body)],
            )
            self.assertEqual(exit_code, 0)
            expected_hash = hashlib.sha256(b"").hexdigest()[:12]
            self.assertTrue((Path(tmp) / f"enceladus_{expected_hash}.ids").is_file())


class PagesLoopTests(unittest.TestCase):
    def _write_census_file(self, tmp, project="enceladus", type_="task", status="open", pages=None):
        pages = pages if pages is not None else [
            {"cursor": None, "n": 50},
            {"cursor": "CURSOR-1", "n": 20},
            {"cursor": "CURSOR-2", "n": 5},
        ]
        body = {
            "count": 75,
            "count_truncated": False,
            "exhausted": True,
            "pages": pages,
            "page_size": 50,
            "as_of": {"kind": "wall_clock+max_updated_at", "started_at": "2026-09-24T05:00:00Z", "max_updated_at": None},
            "order": "record_id_asc",
            "by_type": {"task": 75},
            "ids_inline_cap": 500,
        }
        path = elr_list.census_file_path(tmp, project, type_, status, "2026-09-24T05:00:00Z")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(body), encoding="utf-8")
        return body

    def test_pages_n_less_than_total_reports_lower_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_census_file(tmp)
            page0 = {"success": True, "records": _records([f"ENC-TSK-{i}" for i in range(1, 51)]), "count": 50, "page_size": 50}
            page1 = {"success": True, "records": _records([f"ENC-TSK-{i}" for i in range(51, 71)]), "count": 20, "page_size": 50}
            exit_code, digest, mock_urlopen, _stderr = _run_main(
                ["--project", "enceladus", "--type", "task", "--status", "open", "--lists-dir", tmp, "--pages", "2"],
                [_ok(page0), _ok(page1)],
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(mock_urlopen.call_count, 3)  # health + 2 page fetches
            self.assertTrue(digest["ok"])
            self.assertTrue(digest["lower_bound"])
            self.assertEqual(digest["n"], 70)

            ids_path = Path(tmp) / "enceladus_task_open_pages2.ids"
            self.assertTrue(ids_path.is_file())
            loaded = elr_batch_get.load_ids_file(str(ids_path))
            self.assertEqual(len(loaded), 70)

    def test_pages_n_equal_total_omits_lower_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_census_file(tmp)
            page0 = {"success": True, "records": _records(["ENC-TSK-1"]), "count": 1, "page_size": 50}
            page1 = {"success": True, "records": _records(["ENC-TSK-2"]), "count": 1, "page_size": 50}
            page2 = {"success": True, "records": _records(["ENC-TSK-3"]), "count": 1, "page_size": 50}
            exit_code, digest, mock_urlopen, _stderr = _run_main(
                ["--project", "enceladus", "--type", "task", "--status", "open", "--lists-dir", tmp, "--pages", "3"],
                [_ok(page0), _ok(page1), _ok(page2)],
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(mock_urlopen.call_count, 4)
            self.assertNotIn("lower_bound", digest)

    def test_pages_with_no_matching_census_file_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, digest, mock_urlopen, _stderr = _run_main(
                ["--project", "enceladus", "--lists-dir", tmp, "--pages", "2"],
                [],
            )
            self.assertEqual(exit_code, 1)
            self.assertFalse(digest["ok"])
            self.assertIn("no_matching_census_file", digest["anomalies"])
            self.assertEqual(mock_urlopen.call_count, 1)  # only the health preflight


class RoundTripTests(unittest.TestCase):
    """ENC-TSK-Q16-0C: list --census -> --page <pages[1].cursor> -> batch_get --ids-file."""

    def test_census_then_page_then_batch_get_ids_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            census_body = {
                "count": 70,
                "count_truncated": False,
                "exhausted": True,
                "pages": [
                    {"cursor": None, "first": {"id": "ENC-TSK-1", "status": "open", "title": "t1"}, "last": {"id": "ENC-TSK-50", "status": "open", "title": "t50"}, "n": 50},
                    {"cursor": "CURSOR-1", "first": {"id": "ENC-TSK-51", "status": "open", "title": "t51"}, "last": {"id": "ENC-TSK-70", "status": "open", "title": "t70"}, "n": 20},
                ],
                "page_size": 50,
                "as_of": {"kind": "wall_clock+max_updated_at", "started_at": "2026-09-24T05:00:00Z", "max_updated_at": None},
                "order": "record_id_asc",
                "by_type": {"task": 70},
                "ids_inline_cap": 500,
            }
            exit_code, census_digest, _mock, _stderr = _run_main(
                ["--project", "enceladus", "--lists-dir", tmp, "--census"],
                [_ok(census_body)],
            )
            self.assertEqual(exit_code, 0)
            second_page_cursor = census_digest["pages"][1]["cursor"]
            self.assertEqual(second_page_cursor, "CURSOR-1")

            page_ids = [f"ENC-TSK-{i}" for i in range(51, 71)]
            page_body = {"success": True, "records": _records(page_ids), "count": 20, "page_size": 50}
            exit_code, _page_digest, _mock, _stderr = _run_main(
                ["--project", "enceladus", "--lists-dir", tmp, "--page", second_page_cursor],
                [_ok(page_body)],
            )
            self.assertEqual(exit_code, 0)

            ids_path = elr_list.page_ids_file_path(tmp, "enceladus", second_page_cursor)
            self.assertTrue(ids_path.is_file())

            # batch_get --ids-file round trip: every id 404s (kept offline),
            # proving the file is in the loader's exact expected shape and
            # nothing in it is silently dropped.
            responses = [_http_error(404, json.dumps({"error": f"Record not found: {rid}"}).encode()) for rid in page_ids]
            with patch(_URLOPEN, side_effect=responses):
                batch_digest = elr_batch_get.run_batch_get(elr_batch_get.load_ids_file(str(ids_path)), "prod", 5)
            self.assertEqual(len(batch_digest["rows"]), 20)
            self.assertEqual({r["id"] for r in batch_digest["rows"]}, set(page_ids))


if __name__ == "__main__":
    unittest.main()
