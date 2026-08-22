"""Offline tests for elr_doc_get.py -- disk-landing document fetch with
digest-only return (ENC-TSK-O51, spec DOC-F2CF625B7556 AC-4). No network
access -- urllib.request.urlopen is mocked. No real ~/.enceladus writes --
every test passes an explicit --out-dir / out_dir under a tempdir.
"""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import elr_doc_get


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


def _server_body(doc):
    """Mirror _get_single()'s payload shape:
    {"success": True, "document": doc, **doc}.
    """
    return {"success": True, "document": doc, **doc}


class AllowAbbrevTests(unittest.TestCase):
    """Per the ELR spec, every ELR CLI sets allow_abbrev=False so a
    partial flag (e.g. --out instead of --out-dir) is never silently
    accepted.
    """

    def test_parser_has_allow_abbrev_false(self):
        parser = elr_doc_get.build_parser()
        self.assertFalse(parser.allow_abbrev)

    def test_abbreviated_flag_is_rejected(self):
        parser = elr_doc_get.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(stderr):
                parser.parse_args(["DOC-XYZ", "--out"])

    def test_full_flag_names_are_accepted(self):
        parser = elr_doc_get.build_parser()
        args = parser.parse_args(["DOC-XYZ", "--out-dir", "/tmp/x", "--timeout", "9"])
        self.assertEqual(args.document_id, "DOC-XYZ")
        self.assertEqual(args.out_dir, "/tmp/x")
        self.assertEqual(args.timeout, 9)

    def test_document_id_is_required_positional(self):
        parser = elr_doc_get.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(stderr):
                parser.parse_args([])

    def test_default_out_dir_and_json_flag(self):
        parser = elr_doc_get.build_parser()
        args = parser.parse_args(["DOC-XYZ"])
        self.assertEqual(args.out_dir, elr_doc_get.DEFAULT_OUT_DIR)
        self.assertTrue(args.json)


class OutlineExtractionTests(unittest.TestCase):
    """Fixture markdown covering H1-H3, a deeper H4 that must be
    excluded, and a heading-shaped line inside a fenced code block
    that must be skipped (mirrors the fence-tracking approach in
    backend/lambda/document_api/lambda_function.py's compliance
    scorer, reimplemented standalone since ELR is stdlib-only).
    """

    FIXTURE = (
        "# Title\n"
        "\n"
        "Some intro text.\n"
        "\n"
        "## Section A\n"
        "\n"
        "body text\n"
        "\n"
        "```python\n"
        "# this is a code comment, not a heading\n"
        "```\n"
        "\n"
        "### Sub B\n"
        "\n"
        "#### Too Deep\n"
        "\n"
        "## Section C\n"
    )

    def test_outline_captures_h1_through_h3_with_line_numbers(self):
        outline = elr_doc_get._extract_outline(self.FIXTURE)
        self.assertEqual(
            outline,
            [
                {"level": 1, "line": 1, "text": "Title"},
                {"level": 2, "line": 5, "text": "Section A"},
                {"level": 3, "line": 13, "text": "Sub B"},
                {"level": 2, "line": 17, "text": "Section C"},
            ],
        )

    def test_outline_skips_fenced_code_block_content(self):
        outline = elr_doc_get._extract_outline(self.FIXTURE)
        texts = [entry["text"] for entry in outline]
        self.assertNotIn("this is a code comment, not a heading", texts)

    def test_outline_excludes_h4_and_deeper(self):
        outline = elr_doc_get._extract_outline(self.FIXTURE)
        texts = [entry["text"] for entry in outline]
        self.assertNotIn("Too Deep", texts)

    def test_outline_empty_for_no_headings(self):
        self.assertEqual(elr_doc_get._extract_outline("just prose, no headings\n"), [])


class FetchDocumentDigestTests(unittest.TestCase):
    DOC_ID = "DOC-TESTAAA111"
    CONTENT = "# Title\n\nbody\n\n## Section\n\nmore body\n"

    def _content_hash(self, content=None):
        return hashlib.sha256((content if content is not None else self.CONTENT).encode("utf-8")).hexdigest()

    def test_digest_field_completeness_on_success(self):
        doc = {
            "document_id": self.DOC_ID,
            "version": 3,
            "content_hash": self._content_hash(),
            "compliance_score": 92,
            "content": self.CONTENT,
        }
        fake_resp = _FakeHttpResponse(200, json.dumps(_server_body(doc)).encode("utf-8"))
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                digest = elr_doc_get.fetch_document(self.DOC_ID, tmpdir)

        expected_keys = {
            "operation",
            "ok",
            "status",
            "identity_posture",
            "anomalies",
            "document_id",
            "version",
            "content_hash",
            "local_sha256",
            "size_bytes",
            "compliance_score",
            "outline",
            "local_path",
        }
        self.assertEqual(set(digest.keys()), expected_keys)
        self.assertTrue(digest["ok"])
        self.assertEqual(digest["status"], 200)
        self.assertEqual(digest["operation"], "elr_doc_get.fetch")
        self.assertEqual(digest["document_id"], self.DOC_ID)
        self.assertEqual(digest["version"], 3)
        self.assertEqual(digest["compliance_score"], 92)
        self.assertEqual(digest["size_bytes"], len(self.CONTENT.encode("utf-8")))
        self.assertEqual(digest["anomalies"], [])
        self.assertTrue(digest["local_path"].endswith(f"{self.DOC_ID}.md"))

    def test_digest_is_json_serializable(self):
        doc = {
            "document_id": self.DOC_ID,
            "version": 1,
            "content_hash": self._content_hash(),
            "content": self.CONTENT,
        }
        fake_resp = _FakeHttpResponse(200, json.dumps(_server_body(doc)).encode("utf-8"))
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                digest = elr_doc_get.fetch_document(self.DOC_ID, tmpdir)
        serialized = json.dumps(digest, sort_keys=True)
        self.assertEqual(json.loads(serialized), digest)

    def test_hash_match_no_anomaly(self):
        doc = {
            "document_id": self.DOC_ID,
            "version": 1,
            "content_hash": self._content_hash(),
            "content": self.CONTENT,
        }
        fake_resp = _FakeHttpResponse(200, json.dumps(_server_body(doc)).encode("utf-8"))
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                digest = elr_doc_get.fetch_document(self.DOC_ID, tmpdir)
        self.assertTrue(digest["ok"])
        self.assertEqual(digest["local_sha256"], digest["content_hash"])
        self.assertNotIn("content-hash-mismatch", digest["anomalies"])

    def test_hash_mismatch_sets_anomaly_and_not_ok(self):
        doc = {
            "document_id": self.DOC_ID,
            "version": 1,
            "content_hash": "0" * 64,  # deliberately wrong
            "content": self.CONTENT,
        }
        fake_resp = _FakeHttpResponse(200, json.dumps(_server_body(doc)).encode("utf-8"))
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                digest = elr_doc_get.fetch_document(self.DOC_ID, tmpdir)
        self.assertFalse(digest["ok"])
        self.assertIn("content-hash-mismatch", digest["anomalies"])
        self.assertNotEqual(digest["local_sha256"], digest["content_hash"])

    def test_missing_server_hash_is_noted_but_not_fatal(self):
        doc = {
            "document_id": self.DOC_ID,
            "version": 1,
            "content": self.CONTENT,
            # content_hash intentionally omitted
        }
        fake_resp = _FakeHttpResponse(200, json.dumps(_server_body(doc)).encode("utf-8"))
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                digest = elr_doc_get.fetch_document(self.DOC_ID, tmpdir)
        self.assertTrue(digest["ok"])
        self.assertIn("server-content-hash-missing", digest["anomalies"])

    def test_missing_body_marks_not_ok(self):
        doc = {"document_id": self.DOC_ID, "version": 1, "content_hash": "deadbeef"}
        fake_resp = _FakeHttpResponse(200, json.dumps(_server_body(doc)).encode("utf-8"))
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                digest = elr_doc_get.fetch_document(self.DOC_ID, tmpdir)
        self.assertFalse(digest["ok"])
        self.assertIn("missing-document-body", digest["anomalies"])
        # local_path is an optional digest field, omitted (not None) when
        # nothing was ever saved to disk -- matches build_digest()'s
        # established omit-when-None contract.
        self.assertNotIn("local_path", digest)

    def test_404_not_found_marks_not_ok_and_emits_digest(self):
        fake_resp_body = json.dumps({"error": f"Document not found: {self.DOC_ID}"}).encode("utf-8")
        import urllib.error

        http_error = urllib.error.HTTPError(
            url="https://jreese.net/api/v1/documents/DOC-TESTAAA111",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=io.BytesIO(fake_resp_body),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=http_error):
                digest = elr_doc_get.fetch_document(self.DOC_ID, tmpdir)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], 404)
        self.assertNotIn("local_path", digest)

    def test_saved_file_content_matches_source(self):
        doc = {
            "document_id": self.DOC_ID,
            "version": 1,
            "content_hash": self._content_hash(),
            "content": self.CONTENT,
        }
        fake_resp = _FakeHttpResponse(200, json.dumps(_server_body(doc)).encode("utf-8"))
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                digest = elr_doc_get.fetch_document(self.DOC_ID, tmpdir)
            saved = Path(digest["local_path"]).read_text(encoding="utf-8")
            self.assertEqual(saved, self.CONTENT)

    def test_out_dir_is_created_and_expanded(self):
        doc = {
            "document_id": self.DOC_ID,
            "version": 1,
            "content_hash": self._content_hash(),
            "content": self.CONTENT,
        }
        fake_resp = _FakeHttpResponse(200, json.dumps(_server_body(doc)).encode("utf-8"))
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = str(Path(tmpdir) / "does" / "not" / "exist" / "yet")
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                digest = elr_doc_get.fetch_document(self.DOC_ID, nested)
            self.assertTrue(Path(digest["local_path"]).is_file())


class NoBodyOnStdoutTests(unittest.TestCase):
    """Guarantee: the document body must NEVER be printed. Only the
    digest JSON is allowed on stdout, whether the fetch succeeds or
    fails.
    """

    SECRET_MARKER = "SUPER-SECRET-CONTENT-MARKER-DO-NOT-PRINT-77492"
    DOC_ID = "DOC-SECRETDOC01"

    def test_main_success_never_prints_body(self):
        content = f"# Title\n\n{self.SECRET_MARKER}\n" * 50  # simulate a large body
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        doc = {
            "document_id": self.DOC_ID,
            "version": 1,
            "content_hash": content_hash,
            "content": content,
        }
        fake_resp = _FakeHttpResponse(200, json.dumps(_server_body(doc)).encode("utf-8"))
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                with contextlib.redirect_stdout(stdout):
                    exit_code = elr_doc_get.main([self.DOC_ID, "--out-dir", tmpdir])
            captured = stdout.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertNotIn(self.SECRET_MARKER, captured)
            # exactly one JSON line, and it round-trips
            lines = [line for line in captured.splitlines() if line.strip()]
            self.assertEqual(len(lines), 1)
            parsed = json.loads(lines[0])
            self.assertTrue(parsed["ok"])
            # but the body WAS actually saved to disk
            saved_text = Path(parsed["local_path"]).read_text(encoding="utf-8")
            self.assertIn(self.SECRET_MARKER, saved_text)

    def test_main_failure_never_prints_body_and_exits_nonzero(self):
        doc = {
            "document_id": self.DOC_ID,
            "version": 1,
            "content_hash": "0" * 64,
            "content": f"# Title\n\n{self.SECRET_MARKER}\n",
        }
        fake_resp = _FakeHttpResponse(200, json.dumps(_server_body(doc)).encode("utf-8"))
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
                with contextlib.redirect_stdout(stdout):
                    exit_code = elr_doc_get.main([self.DOC_ID, "--out-dir", tmpdir])
        captured = stdout.getvalue()
        self.assertNotEqual(exit_code, 0)
        self.assertNotIn(self.SECRET_MARKER, captured)
        parsed = json.loads(captured.strip())
        self.assertFalse(parsed["ok"])
        self.assertIn("content-hash-mismatch", parsed["anomalies"])

    def test_main_transport_failure_still_emits_digest_never_raises(self):
        import urllib.error

        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch(
                "elr_lib.transport.urllib.request.urlopen",
                side_effect=urllib.error.URLError("connection refused"),
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = elr_doc_get.main([self.DOC_ID, "--out-dir", tmpdir])
        self.assertNotEqual(exit_code, 0)
        parsed = json.loads(stdout.getvalue().strip())
        self.assertFalse(parsed["ok"])
        self.assertEqual(parsed["status"], 0)


if __name__ == "__main__":
    unittest.main()
