"""Offline tests for elr_doc_patch.py -- the delta-only heading-anchored
section patch client (ENC-TSK-P78, T-B5, FR-B4-11..14, AC-3/AC-4/AC-5).
No network access -- urllib.request.urlopen is mocked per-test via a
small method/url dispatcher (plane_safety's sentinel + count probes,
the health governance_hash probe, and the sections POST all go through
the SAME mocked urlopen, so each test must route all three). No real
~/.enceladus writes -- every test passes an explicit docs_dir under a
tempdir.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import elr_doc_patch
from elr_lib import manifest as elr_manifest
from elr_lib import plane_safety
from elr_lib import sections as elr_sections

MD = "# Title\n\n## Section A\n\nold body a\n\n## Section B\n\nbody b\n"
CONTENT_HASH = hashlib.sha256(MD.encode("utf-8")).hexdigest()
HEALTH_BODY = json.dumps({"governance_hash": "gh" + "0" * 30}).encode("utf-8")
SENTINEL_BODY = json.dumps({"document_id": plane_safety.SENTINEL_DOCUMENT_ID, "version": 1}).encode("utf-8")
LIST_BODY = json.dumps({"documents": [], "count": 0}).encode("utf-8")


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


def _seed(tmp, *, document_id="DOC-X", content=MD, content_hash=None, fetched_at=None):
    resolved_hash = content_hash or (hashlib.sha256(content.encode("utf-8")).hexdigest() if content is not None else CONTENT_HASH)
    elr_manifest.write_side_file(
        document_id,
        {
            "document_id": document_id,
            "version": 1,
            "content_hash": resolved_hash,
            "size_bytes": len(content.encode("utf-8")) if content is not None else None,
            "outline": [],
        },
        docs_dir=tmp,
        fetched_at=fetched_at,
    )
    if content is not None:
        (Path(tmp) / f"{document_id}.md").write_text(content, encoding="utf-8")


def _make_urlopen(*, post_status=200, post_body=b"{}", raise_http_error=False):
    """Routes health/sentinel-probe/count-probe/sections-POST calls by
    method + URL, exactly as a real InternalClient session would issue
    them during patch_section()'s plane-safety pre-flight + write.
    """

    def fake_urlopen(req, timeout=None, context=None):
        url = req.full_url
        method = req.get_method()
        if url.endswith("/health"):
            return _FakeHttpResponse(200, HEALTH_BODY)
        if method == "POST" and "/sections" in url:
            if raise_http_error:
                raise urllib.error.HTTPError(url=url, code=post_status, msg="x", hdrs=None, fp=io.BytesIO(post_body))
            return _FakeHttpResponse(post_status, post_body)
        if plane_safety.SENTINEL_DOCUMENT_ID in url:
            return _FakeHttpResponse(200, SENTINEL_BODY)
        if method == "GET":
            return _FakeHttpResponse(200, LIST_BODY)
        raise AssertionError(f"unexpected mocked call: {method} {url}")

    return fake_urlopen


def _server_apply(md, anchor, op, body, *, block_id="SERVERBLOCKID0000000000001", **kwargs):
    """Compute what the SERVER would actually produce for an op (used to
    build a realistic 200 response body in tests), with a fixed ULID
    standing in for the server's own nondeterministic stamp.
    """
    entries = elr_sections.compute_outline_with_spans(md)
    entry = elr_sections.resolve_anchor(entries, anchor)
    return elr_sections.apply_section_op(md, entry, op, body, ulid_factory=lambda *a, **k: block_id, **kwargs)


class AllowAbbrevTests(unittest.TestCase):
    def test_parser_has_allow_abbrev_false(self):
        self.assertFalse(elr_doc_patch.build_parser().allow_abbrev)

    def test_anchor_and_block_id_are_mutually_exclusive(self):
        parser = elr_doc_patch.build_parser()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["--doc", "DOC-X", "--anchor", "A", "--block-id", "B", "--op", "replace"])

    def test_anchor_or_block_id_required(self):
        parser = elr_doc_patch.build_parser()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["--doc", "DOC-X", "--op", "replace"])

    def test_op_choices_enforced(self):
        parser = elr_doc_patch.build_parser()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["--doc", "DOC-X", "--anchor", "A", "--op", "bogus"])


class AnchorParsingTests(unittest.TestCase):
    def test_heading_path_split_on_separator(self):
        self.assertEqual(elr_doc_patch.parse_heading_path("Section A / Sub B"), ["Section A", "Sub B"])

    def test_single_segment(self):
        self.assertEqual(elr_doc_patch.parse_heading_path("Section A"), ["Section A"])

    def test_build_anchor_heading_path(self):
        anchor = elr_doc_patch.build_anchor(heading_path_raw="A / B", block_id=None, ordinal=2)
        self.assertEqual(anchor, {"heading_path": ["A", "B"], "ordinal": 2})

    def test_build_anchor_block_id(self):
        anchor = elr_doc_patch.build_anchor(heading_path_raw=None, block_id="BLK1", ordinal=None)
        self.assertEqual(anchor, {"block_id": "BLK1"})


class LocalValidationTests(unittest.TestCase):
    def test_delete_with_body_is_refused_locally(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            digest, code = elr_doc_patch.patch_section(
                "DOC-X", {"heading_path": ["Section A"]}, "delete", "unexpected body", docs_dir=tmp
            )
        self.assertEqual(code, elr_doc_patch.EXIT_REFUSED)
        self.assertFalse(digest["ok"])
        self.assertTrue(any("OP_BODY_FORBIDDEN" in a for a in digest["anomalies"]))

    def test_replace_without_body_is_refused_locally(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            digest, code = elr_doc_patch.patch_section(
                "DOC-X", {"heading_path": ["Section A"]}, "replace", None, docs_dir=tmp
            )
        self.assertEqual(code, elr_doc_patch.EXIT_REFUSED)
        self.assertTrue(any("OP_BODY_REQUIRED" in a for a in digest["anomalies"]))

    def test_oversized_body_is_refused_locally(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            digest, code = elr_doc_patch.patch_section(
                "DOC-X", {"heading_path": ["Section A"]}, "replace",
                "x" * (elr_sections.MAX_BODY_BYTES + 1), docs_dir=tmp,
            )
        self.assertEqual(code, elr_doc_patch.EXIT_REFUSED)
        self.assertTrue(any("BODY_TOO_LARGE" in a for a in digest["anomalies"]))


class PreconditionTests(unittest.TestCase):
    def test_missing_side_file_exits_2_with_remediation(self):
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = elr_doc_patch.patch_section(
                "DOC-NEVER-FETCHED", {"heading_path": ["A"]}, "replace", "x", docs_dir=tmp
            )
        self.assertEqual(code, elr_doc_patch.EXIT_PRECONDITION_MISSING_OR_STALE)
        self.assertFalse(digest["ok"])
        self.assertIn("elr_doc_digest.py --doc DOC-NEVER-FETCHED", digest["remediation"])

    def test_stale_side_file_exits_2(self):
        import datetime

        old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=25)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp, fetched_at=old)
            digest, code = elr_doc_patch.patch_section("DOC-X", {"heading_path": ["Section A"]}, "replace", "x", docs_dir=tmp)
        self.assertEqual(code, elr_doc_patch.EXIT_PRECONDITION_MISSING_OR_STALE)

    def test_fresh_side_file_passes_precondition_gate(self):
        # A fresh-but-otherwise-doomed run (no network mocked -> urlopen
        # raises) proves the precondition gate itself was satisfied,
        # since it gets past exit 2 and fails later instead.
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            with patch(
                "elr_lib.transport.urllib.request.urlopen",
                side_effect=urllib.error.URLError("no network in this test"),
            ):
                digest, code = elr_doc_patch.patch_section(
                    "DOC-X", {"heading_path": ["Section A"]}, "replace", "x", docs_dir=tmp
                )
        self.assertNotEqual(code, elr_doc_patch.EXIT_PRECONDITION_MISSING_OR_STALE)


class DryRunTests(unittest.TestCase):
    def test_dry_run_renders_diff_no_network_and_exits_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            diff_stream = io.StringIO()
            with patch(
                "elr_lib.transport.urllib.request.urlopen",
                side_effect=AssertionError("dry-run must never touch the network"),
            ):
                digest, code = elr_doc_patch.patch_section(
                    "DOC-X", {"heading_path": ["Section A"]}, "replace", "new body a",
                    dry_run=True, docs_dir=tmp, diff_stream=diff_stream,
                )
        self.assertEqual(code, elr_doc_patch.EXIT_OK)
        self.assertTrue(digest["ok"])
        self.assertEqual(digest["status"], "dry-run")
        self.assertIn("dry-run-no-network-write", digest["anomalies"])
        rendered = diff_stream.getvalue()
        self.assertIn("-old body a", rendered)
        self.assertIn("+new body a", rendered)

    def test_dry_run_without_local_cache_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp, content=None)  # side file only, no .md cache
            digest, code = elr_doc_patch.patch_section(
                "DOC-X", {"heading_path": ["Section A"]}, "replace", "x", dry_run=True, docs_dir=tmp,
            )
        self.assertEqual(code, elr_doc_patch.EXIT_REFUSED)
        self.assertIn("local-body-cache-missing", digest["anomalies"])

    def test_dry_run_anchor_not_found_exits_5(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            digest, code = elr_doc_patch.patch_section(
                "DOC-X", {"heading_path": ["Does Not Exist"]}, "replace", "x", dry_run=True, docs_dir=tmp,
            )
        self.assertEqual(code, elr_doc_patch.EXIT_ANCHOR_NOT_FOUND)
        self.assertIn("outline", digest)


class SuccessPathTests(unittest.TestCase):
    def test_200_updates_side_file_and_reapplies_local_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            anchor = {"heading_path": ["Section A"]}
            result = _server_apply(MD, anchor, "replace", "new body a")
            new_content = result["content"]
            new_hash = hashlib.sha256(new_content.encode("utf-8")).hexdigest()
            resp_body = json.dumps({
                "success": True, "document_id": "DOC-X", "version": 2, "content_hash": new_hash,
                "size_bytes": len(new_content.encode("utf-8")), "event_id": "EVT01",
                "anchor_resolved": {"heading_path": ["Section A"], "level": 2, "ordinal": 1, "block_id": result["block_id"]},
                "bytes_changed": result["bytes_changed"], "outline": [],
            }).encode("utf-8")

            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=_make_urlopen(post_status=200, post_body=resp_body)):
                digest, code = elr_doc_patch.patch_section("DOC-X", anchor, "replace", "new body a", docs_dir=tmp)

            self.assertEqual(code, elr_doc_patch.EXIT_OK)
            self.assertTrue(digest["ok"])
            self.assertEqual(digest["version"], 2)
            self.assertEqual(digest["content_hash"], new_hash)
            self.assertEqual(digest["event_id"], "EVT01")
            self.assertNotIn("local-reapply-hash-mismatch", digest["anomalies"])

            cached = (Path(tmp) / "DOC-X.md").read_text(encoding="utf-8")
            self.assertEqual(cached, new_content)

            side = elr_manifest.read_side_file("DOC-X", docs_dir=tmp)
            self.assertEqual(side["content_hash"], new_hash)
            self.assertEqual(side["version"], 2)

    def test_200_without_local_cache_skips_reapply_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            (Path(tmp) / "DOC-X.md").unlink()  # side file stays, body cache doesn't
            anchor = {"heading_path": ["Section A"]}
            resp_body = json.dumps({
                "success": True, "document_id": "DOC-X", "version": 2, "content_hash": "f" * 64,
                "event_id": "EVT02", "anchor_resolved": {"block_id": "X"}, "bytes_changed": 3, "outline": [],
            }).encode("utf-8")
            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=_make_urlopen(post_status=200, post_body=resp_body)):
                digest, code = elr_doc_patch.patch_section("DOC-X", anchor, "replace", "x", docs_dir=tmp)
        self.assertEqual(code, elr_doc_patch.EXIT_OK)
        self.assertTrue(digest["ok"])
        self.assertNotIn("local-reapply-hash-mismatch", digest["anomalies"])

    def test_delete_op_sends_no_body_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            anchor = {"heading_path": ["Section A"]}
            resp_body = json.dumps({
                "success": True, "document_id": "DOC-X", "version": 2, "content_hash": "e" * 64,
                "event_id": "EVT03", "anchor_resolved": {"block_id": None}, "bytes_changed": 3, "outline": [],
            }).encode("utf-8")

            captured_payloads = []
            base_fake = _make_urlopen(post_status=200, post_body=resp_body)

            def capturing_urlopen(req, timeout=None, context=None):
                if req.get_method() == "POST" and "/sections" in req.full_url:
                    captured_payloads.append(json.loads(req.data.decode("utf-8")))
                return base_fake(req, timeout=timeout, context=context)

            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=capturing_urlopen):
                digest, code = elr_doc_patch.patch_section("DOC-X", anchor, "delete", None, docs_dir=tmp)

        self.assertEqual(code, elr_doc_patch.EXIT_OK)
        self.assertEqual(len(captured_payloads), 1)
        self.assertNotIn("body", captured_payloads[0])
        self.assertEqual(captured_payloads[0]["op"], "delete")
        self.assertEqual(captured_payloads[0]["if_match"], CONTENT_HASH)
        self.assertIn("governance_hash", captured_payloads[0])

    def test_include_heading_and_no_rebase_only_sent_when_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            anchor = {"heading_path": ["Section A"]}
            resp_body = json.dumps({
                "success": True, "document_id": "DOC-X", "version": 2, "content_hash": "e" * 64,
                "event_id": "EVT04", "anchor_resolved": {"block_id": None}, "bytes_changed": 1, "outline": [],
            }).encode("utf-8")
            captured_payloads = []
            base_fake = _make_urlopen(post_status=200, post_body=resp_body)

            def capturing_urlopen(req, timeout=None, context=None):
                if req.get_method() == "POST" and "/sections" in req.full_url:
                    captured_payloads.append(json.loads(req.data.decode("utf-8")))
                return base_fake(req, timeout=timeout, context=context)

            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=capturing_urlopen):
                elr_doc_patch.patch_section("DOC-X", anchor, "replace", "x", docs_dir=tmp)

        payload = captured_payloads[0]
        self.assertNotIn("include_heading", payload)
        self.assertNotIn("rebase_headings", payload)


class ByteBudgetTests(unittest.TestCase):
    def test_request_bytes_under_4096_for_large_document(self):
        # A >60KB fixture document, but only a 1000-byte section body --
        # the delta-only contract means the wire request never scales
        # with document size.
        big_doc = "# Title\n\n" + "".join(f"## Section {i}\n\nfiller filler filler.\n\n" for i in range(2000))
        self.assertGreater(len(big_doc.encode("utf-8")), 60_000)

        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp, content=big_doc)
            anchor = {"heading_path": ["Section 500"]}
            body = "y" * 1000
            result = _server_apply(big_doc, anchor, "replace", body)
            new_hash = hashlib.sha256(result["content"].encode("utf-8")).hexdigest()
            resp_body = json.dumps({
                "success": True, "document_id": "DOC-X", "version": 2, "content_hash": new_hash,
                "event_id": "EVT05", "anchor_resolved": {"block_id": result["block_id"]},
                "bytes_changed": result["bytes_changed"], "outline": [],
            }).encode("utf-8")

            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=_make_urlopen(post_status=200, post_body=resp_body)):
                digest, code = elr_doc_patch.patch_section("DOC-X", anchor, "replace", body, docs_dir=tmp)

        self.assertEqual(code, elr_doc_patch.EXIT_OK)
        self.assertIn("request_bytes", digest)
        self.assertLess(digest["request_bytes"], 4096)


class FailureEnvelopeTests(unittest.TestCase):
    def test_412_refreshes_side_file_and_exits_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            anchor = {"heading_path": ["Section A"]}
            body412 = json.dumps({
                "success": False, "error": "mismatch", "current_hash": "d" * 64,
                "current_version": 9, "recommended_next_actions": ["re-read digest via documents.manifest and retry"],
            }).encode("utf-8")
            with patch(
                "elr_lib.transport.urllib.request.urlopen",
                side_effect=_make_urlopen(post_status=412, post_body=body412, raise_http_error=True),
            ):
                digest, code = elr_doc_patch.patch_section("DOC-X", anchor, "replace", "new body a", docs_dir=tmp)

            self.assertEqual(code, elr_doc_patch.EXIT_CONTENT_HASH_MISMATCH)
            self.assertFalse(digest["ok"])
            self.assertEqual(digest["current_hash"], "d" * 64)
            self.assertEqual(digest["current_version"], 9)
            self.assertEqual(digest["recommended_next_actions"], ["re-read digest via documents.manifest and retry"])

            side = elr_manifest.read_side_file("DOC-X", docs_dir=tmp)
            self.assertEqual(side["content_hash"], "d" * 64)
            self.assertEqual(side["version"], 9)

    def test_404_reports_outline_and_exits_5(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            anchor = {"heading_path": ["Section A"]}
            outline = [{"heading_path": ["X"], "level": 1, "ordinal": 1, "block_id": None, "line_start": 1, "line_end": 1, "section_bytes": 0}]
            body404 = json.dumps({"success": False, "error": "not found", "outline": outline}).encode("utf-8")
            with patch(
                "elr_lib.transport.urllib.request.urlopen",
                side_effect=_make_urlopen(post_status=404, post_body=body404, raise_http_error=True),
            ):
                digest, code = elr_doc_patch.patch_section("DOC-X", anchor, "replace", "new body a", docs_dir=tmp)

        self.assertEqual(code, elr_doc_patch.EXIT_ANCHOR_NOT_FOUND)
        self.assertEqual(digest["outline"], outline)

    def test_409_reports_candidates_and_exits_6(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            anchor = {"heading_path": ["Section A"]}
            candidates = [
                {"heading_path": ["Section A"], "ordinal": 1, "block_id": None},
                {"heading_path": ["Section A"], "ordinal": 2, "block_id": None},
            ]
            body409 = json.dumps({"success": False, "error": "ambiguous", "candidates": candidates}).encode("utf-8")
            with patch(
                "elr_lib.transport.urllib.request.urlopen",
                side_effect=_make_urlopen(post_status=409, post_body=body409, raise_http_error=True),
            ):
                digest, code = elr_doc_patch.patch_section("DOC-X", anchor, "replace", "new body a", docs_dir=tmp)

        self.assertEqual(code, elr_doc_patch.EXIT_ANCHOR_AMBIGUOUS)
        self.assertEqual(digest["candidates"], candidates)

    def test_plane_safety_sentinel_mismatch_aborts_before_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            anchor = {"heading_path": ["Section A"]}

            def bad_sentinel_urlopen(req, timeout=None, context=None):
                url = req.full_url
                if url.endswith("/health"):
                    return _FakeHttpResponse(200, HEALTH_BODY)
                if plane_safety.SENTINEL_DOCUMENT_ID in url:
                    # Wrong plane: sentinel does not echo back correctly.
                    return _FakeHttpResponse(200, json.dumps({"document_id": "WRONG"}).encode("utf-8"))
                if req.get_method() == "POST":
                    raise AssertionError("must never reach the write after a plane-safety abort")
                return _FakeHttpResponse(200, LIST_BODY)

            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=bad_sentinel_urlopen):
                digest, code = elr_doc_patch.patch_section("DOC-X", anchor, "replace", "new body a", docs_dir=tmp)

        self.assertEqual(code, elr_doc_patch.EXIT_REFUSED)
        self.assertFalse(digest["ok"])
        self.assertIn("plane-safety-sentinel-mismatch", digest["anomalies"])


class LocalReapplyMismatchTests(unittest.TestCase):
    def test_stale_local_cache_skips_reapply_and_refetches(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            # Corrupt the local cache so its sha256 no longer matches if_match.
            (Path(tmp) / "DOC-X.md").write_text(MD + "\nSTALE EDIT\n", encoding="utf-8")

            anchor = {"heading_path": ["Section A"]}
            refetched_content = "# Title\n\nserver truth after refetch\n"
            resp_body = json.dumps({
                "success": True, "document_id": "DOC-X", "version": 2, "content_hash": "e" * 64,
                "event_id": "EVT06", "anchor_resolved": {"block_id": None}, "bytes_changed": 3, "outline": [],
            }).encode("utf-8")

            def fake_urlopen(req, timeout=None, context=None):
                url = req.full_url
                method = req.get_method()
                if url.endswith("/health"):
                    return _FakeHttpResponse(200, HEALTH_BODY)
                if method == "POST" and "/sections" in url:
                    return _FakeHttpResponse(200, resp_body)
                if plane_safety.SENTINEL_DOCUMENT_ID in url:
                    return _FakeHttpResponse(200, SENTINEL_BODY)
                if method == "GET" and "include_content=true" in url:
                    doc = {"document_id": "DOC-X", "content": refetched_content}
                    return _FakeHttpResponse(200, json.dumps({"document": doc, **doc}).encode("utf-8"))
                return _FakeHttpResponse(200, LIST_BODY)

            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=fake_urlopen):
                digest, code = elr_doc_patch.patch_section("DOC-X", anchor, "replace", "new body a", docs_dir=tmp)

            self.assertEqual(code, elr_doc_patch.EXIT_OK)
            self.assertIn("local-body-cache-stale-skipped-reapply", digest["anomalies"])
            cached = (Path(tmp) / "DOC-X.md").read_text(encoding="utf-8")
            self.assertEqual(cached, refetched_content)


class MainCliTests(unittest.TestCase):
    def test_main_dry_run_argv_reads_body_file_and_exits_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed(tmp)
            body_path = Path(tmp) / "body.md"
            body_path.write_text("new body a", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch(
                "elr_lib.transport.urllib.request.urlopen",
                side_effect=AssertionError("dry-run must never touch the network"),
            ):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = elr_doc_patch.main([
                        "--doc", "DOC-X", "--anchor", "Section A", "--op", "replace",
                        "--body-file", str(body_path), "--dry-run", "--docs-dir", tmp,
                    ])
        self.assertEqual(exit_code, 0)
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertTrue(parsed["ok"])
        self.assertIn("-old body a", stderr.getvalue())

    def test_main_precondition_missing_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            body_path = Path(tmp) / "body.md"
            body_path.write_text("new body", encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = elr_doc_patch.main([
                    "--doc", "DOC-NEVER", "--anchor", "Section A", "--op", "replace",
                    "--body-file", str(body_path), "--docs-dir", tmp,
                ])
        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
