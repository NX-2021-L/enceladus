"""Offline tests for elr_doc_digest.py -- documents.manifest fetch +
digest side-file write (ENC-TSK-P78 AC-1). No network access --
urllib.request.urlopen is mocked. No real ~/.enceladus writes -- every
test passes an explicit --docs-dir / docs_dir under a tempdir.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import elr_doc_digest
from elr_lib import manifest as elr_manifest


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


MANIFEST = {
    "document_id": "DOC-TESTAAA111",
    "version": 3,
    "content_hash": "a" * 64,
    "size_bytes": 12345,
    "outline": [{"heading_path": [], "level": 1, "ordinal": 1, "block_id": None, "line_start": 2, "line_end": 2, "section_bytes": 0}],
}


class AllowAbbrevTests(unittest.TestCase):
    def test_parser_has_allow_abbrev_false(self):
        parser = elr_doc_digest.build_parser()
        self.assertFalse(parser.allow_abbrev)

    def test_abbreviated_flag_is_rejected(self):
        parser = elr_doc_digest.build_parser()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["DOC-X", "--doc"])

    def test_document_id_is_required_positional(self):
        parser = elr_doc_digest.build_parser()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args([])

    def test_defaults(self):
        parser = elr_doc_digest.build_parser()
        args = parser.parse_args(["DOC-X"])
        self.assertEqual(args.docs_dir, elr_manifest.DEFAULT_DOCS_DIR)
        self.assertTrue(args.json)
        self.assertEqual(args.profile, "prod")


class FetchDigestTests(unittest.TestCase):
    def test_success_writes_side_file_and_digest_fields(self):
        fake_resp = _FakeHttpResponse(200, json.dumps(MANIFEST).encode("utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                digest = elr_doc_digest.fetch_digest("DOC-TESTAAA111", tmp)

            self.assertTrue(digest["ok"])
            self.assertEqual(digest["status"], 200)
            self.assertEqual(digest["document_id"], "DOC-TESTAAA111")
            self.assertEqual(digest["version"], 3)
            self.assertEqual(digest["content_hash"], "a" * 64)
            self.assertEqual(digest["size_bytes"], 12345)
            self.assertEqual(digest["anomalies"], [])
            self.assertTrue(digest["digest_path"].endswith("DOC-TESTAAA111.digest.json"))

            side = elr_manifest.read_side_file("DOC-TESTAAA111", docs_dir=tmp)
            self.assertEqual(side["content_hash"], "a" * 64)
            self.assertIn("fetched_at", side)

    def test_digest_is_json_serializable(self):
        fake_resp = _FakeHttpResponse(200, json.dumps(MANIFEST).encode("utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                digest = elr_doc_digest.fetch_digest("DOC-TESTAAA111", tmp)
        self.assertEqual(json.loads(json.dumps(digest, sort_keys=True)), digest)

    def test_404_not_found_marks_not_ok_no_side_file(self):
        import urllib.error

        http_error = urllib.error.HTTPError(
            url="https://jreese.net/api/v1/documents/DOC-X/manifest",
            code=404, msg="Not Found", hdrs=None,
            fp=io.BytesIO(json.dumps({"error": "not found"}).encode("utf-8")),
        )
        with tempfile.TemporaryDirectory() as tmp:
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=http_error):
                digest = elr_doc_digest.fetch_digest("DOC-X", tmp)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], 404)
        self.assertNotIn("digest_path", digest)
        self.assertIsNone(elr_manifest.read_side_file("DOC-X", docs_dir=tmp))

    def test_transport_failure_emits_digest_never_raises(self):
        import urllib.error

        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "elr_lib.transport.urllib.request.urlopen",
                side_effect=urllib.error.URLError("connection refused"),
            ):
                digest = elr_doc_digest.fetch_digest("DOC-X", tmp)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], 0)


class MainStdoutTests(unittest.TestCase):
    def test_main_success_exactly_one_json_line(self):
        fake_resp = _FakeHttpResponse(200, json.dumps(MANIFEST).encode("utf-8"))
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                with contextlib.redirect_stdout(stdout):
                    exit_code = elr_doc_digest.main(["DOC-TESTAAA111", "--docs-dir", tmp])
        self.assertEqual(exit_code, 0)
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertTrue(parsed["ok"])

    def test_main_failure_exits_nonzero(self):
        import urllib.error

        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "elr_lib.transport.urllib.request.urlopen",
                side_effect=urllib.error.URLError("down"),
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = elr_doc_digest.main(["DOC-X", "--docs-dir", tmp])
        self.assertNotEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
