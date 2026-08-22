"""Offline tests for elr_publish.py -- the dual-proof governed document
write path (DOC-F2CF625B7556 A.9, ENC-TSK-O54). No network access:
urllib.request.urlopen is mocked at both call sites in play
(elr_lib.transport for the target-plane InternalClient, and
elr_lib.plane_safety for the bare plane-B client). The live governance
dictionary pull is bypassed by monkeypatching elr_validate.fetch_dictionary
/ load_overlay directly with a small fixture mirroring the REAL live
shapes (document.create has real Layer-1 min_length:1 on title/content;
document.<subtype> pins the document_subtype enum) verified 2026-08-22.
"""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import elr_publish
import elr_validate as ev

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURE_DICTIONARY = {
    "version": "test-fixture-o54",
    "entities": {
        "document.create": {
            "fields": {
                "project_id": {"type": "string", "constraints": {"pattern": "^[a-z0-9_-]+$"}},
                "title": {"type": "string", "constraints": {"min_length": 1, "max_length": 500}},
                "content": {"type": "string", "constraints": {"min_length": 1, "max_bytes": 1048576}},
            }
        },
        "document.doc": {"fields": {"document_subtype": {"type": "enum", "enum": ["doc"]}}},
        "document.idea": {"fields": {"document_subtype": {"type": "enum", "enum": ["idea"]}}},
    },
}

SOURCE_TEXT = (
    "# {DOCID} Test Document\n\n"
    "Body text used across elr_publish.py's dual-proof pass tests.\n\n"
    "## Section\n\nMore body.\n"
)
SOURCE_BYTES = SOURCE_TEXT.encode("utf-8")
SOURCE_SHA256 = hashlib.sha256(SOURCE_BYTES).hexdigest()
MINTED_ID = "DOC-MINTEDABCDEF"


def _fetch_dictionary_ok():
    return {
        "ok": True,
        "auth_path": "fallback-internal-key",
        "status": 200,
        "source_route": "https://jreese.net/api/v1/governance/governance_data_dictionary.json",
        "dictionary": FIXTURE_DICTIONARY,
        "version": FIXTURE_DICTIONARY["version"],
        "entity_count": len(FIXTURE_DICTIONARY["entities"]),
        "size_bytes": 123,
        "content_hash": "fixturehash",
        "error": None,
        "anomalies": [],
    }


def _fetch_dictionary_unreachable():
    return {
        "ok": False,
        "auth_path": "no-auth-available",
        "status": 0,
        "source_route": "https://jreese.net/api/v1/governance/governance_data_dictionary.json",
        "dictionary": None,
        "version": None,
        "entity_count": None,
        "size_bytes": None,
        "content_hash": None,
        "error": "dictionary pull failed: unreachable",
        "anomalies": [],
    }


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


def _doc_body(doc):
    return {"success": True, "document": doc, **doc}


def _http_error(code, body=b""):
    return urllib.error.HTTPError(
        url="https://jreese.net/api/v1/documents", code=code, msg="error", hdrs=None, fp=io.BytesIO(body)
    )


def _sentinel_resp():
    return _FakeHttpResponse(
        200,
        json.dumps(_doc_body({"document_id": "DOC-87EC08ECF51A", "version": 5})).encode("utf-8"),
    )


def _count_probe_resp(sample_ids=None):
    ids = sample_ids if sample_ids is not None else ["DOC-AAA111111111", "DOC-BBB222222222"]
    docs = [{"document_id": i} for i in ids]
    return _FakeHttpResponse(
        200,
        json.dumps({"success": True, "documents": docs, "count": len(docs), "total_matches": len(docs)}).encode(
            "utf-8"
        ),
    )


def _put_resp(content_hash=SOURCE_SHA256, size_bytes=None, compliance_score=90, document_id=MINTED_ID):
    body = {
        "success": True,
        "document_id": document_id,
        "s3_location": f"s3://bucket/{document_id}.md",
        "content_hash": content_hash,
        "size_bytes": size_bytes if size_bytes is not None else len(SOURCE_BYTES),
        "created_at": "2026-08-22T00:00:00Z",
        "compliance_score": compliance_score,
        "compliance_warnings": [],
    }
    return _FakeHttpResponse(201, json.dumps(body).encode("utf-8"))


def _guard_resp(content_hash=SOURCE_SHA256, version=1):
    doc = {"document_id": MINTED_ID, "content_hash": content_hash, "version": version, "size_bytes": len(SOURCE_BYTES)}
    return _FakeHttpResponse(200, json.dumps(_doc_body(doc)).encode("utf-8"))


def _patch_resp(version=2, compliance_score=95, status=200):
    body = {
        "success": True,
        "document_id": MINTED_ID,
        "updated_at": "2026-08-22T00:05:00Z",
        "version": version,
        "compliance_score": compliance_score,
        "compliance_warnings": [],
    }
    return _FakeHttpResponse(status, json.dumps(body).encode("utf-8"))


def _patched_content():
    return SOURCE_TEXT.replace("{DOCID}", MINTED_ID)


def _reread_resp(content=None, version=2, compliance_score=95):
    stored = content if content is not None else _patched_content()
    stored_bytes = stored.encode("utf-8")
    doc = {
        "document_id": MINTED_ID,
        "content": stored,
        "content_hash": hashlib.sha256(stored_bytes).hexdigest(),
        "size_bytes": len(stored_bytes),
        "version": version,
        "compliance_score": compliance_score,
    }
    return _FakeHttpResponse(200, json.dumps(_doc_body(doc)).encode("utf-8"))


def _post_probe_resp(version=2, compliance_score=95, content_hash=None):
    stored_bytes = _patched_content().encode("utf-8")
    doc = {
        "document_id": MINTED_ID,
        "content_hash": content_hash or hashlib.sha256(stored_bytes).hexdigest(),
        "version": version,
        "size_bytes": len(stored_bytes),
        "compliance_score": compliance_score,
    }
    return _FakeHttpResponse(200, json.dumps(_doc_body(doc)).encode("utf-8"))


def _write_source(tmpdir, text=SOURCE_TEXT):
    path = Path(tmpdir) / "source.md"
    path.write_text(text, encoding="utf-8")
    return str(path)


def _patched_preflight():
    return patch.multiple(
        ev,
        fetch_dictionary=lambda timeout=20: _fetch_dictionary_ok(),
        load_overlay=lambda path=None: ([], None),
    )


# ---------------------------------------------------------------------------
# CLI shape
# ---------------------------------------------------------------------------


class AllowAbbrevTests(unittest.TestCase):
    def test_parser_has_allow_abbrev_false(self):
        parser = elr_publish.build_parser()
        self.assertFalse(parser.allow_abbrev)

    def test_abbreviated_flag_is_rejected(self):
        parser = elr_publish.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(stderr):
                parser.parse_args(["source.md", "--tit", "X"])

    def test_source_file_is_required_positional(self):
        parser = elr_publish.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(stderr):
                parser.parse_args(["--title", "X"])

    def test_title_is_required(self):
        parser = elr_publish.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(stderr):
                parser.parse_args(["source.md"])

    def test_defaults(self):
        parser = elr_publish.build_parser()
        args = parser.parse_args(["source.md", "--title", "X"])
        self.assertEqual(args.subtype, "doc")
        self.assertEqual(args.project, "enceladus")
        self.assertEqual(args.placeholder, "{DOCID}")
        self.assertEqual(args.preserve_dir, elr_publish.DEFAULT_PRESERVE_DIR)
        self.assertTrue(args.json)


class SplitCsvTests(unittest.TestCase):
    def test_none_returns_empty(self):
        self.assertEqual(elr_publish._split_csv(None), [])

    def test_splits_and_strips(self):
        self.assertEqual(elr_publish._split_csv("a, b ,c"), ["a", "b", "c"])

    def test_drops_empty_segments(self):
        self.assertEqual(elr_publish._split_csv("a,,b"), ["a", "b"])


# ---------------------------------------------------------------------------
# PRE-FLIGHT
# ---------------------------------------------------------------------------


class PreflightTests(unittest.TestCase):
    def test_dictionary_unreachable_fails_closed_before_any_write(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            with patch.object(ev, "fetch_dictionary", return_value=_fetch_dictionary_unreachable()):
                with patch("elr_lib.transport.urllib.request.urlopen") as mock_urlopen:
                    digest = elr_publish.publish_document(source, "Title", preserve_dir=f"{tmpdir}/preserved")
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "dictionary_unreachable")
        mock_urlopen.assert_not_called()

    def test_empty_title_refused_before_any_write(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen") as mock_urlopen:
                    digest = elr_publish.publish_document(
                        source, "", preserve_dir=f"{tmpdir}/preserved"
                    )
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "validation_failed")
        # The live document.create entity encodes "non-empty" via
        # constraints.min_length (verified 2026-08-22), not a
        # constraints.required flag -- so this surfaces as a
        # constraint_violation on path "title" in violations, not as a
        # missing_fields entry (that list is reserved for Layer 1/2
        # "missing_required" kind violations).
        violation_paths = {v.get("path") for v in digest["refusal"]["violations"]}
        self.assertIn("title", violation_paths)
        mock_urlopen.assert_not_called()

    def test_unknown_subtype_refused_before_any_write(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen") as mock_urlopen:
                    digest = elr_publish.publish_document(
                        source, "Title", subtype="not-a-real-subtype", preserve_dir=f"{tmpdir}/preserved"
                    )
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "validation_failed")
        mock_urlopen.assert_not_called()

    def test_unreadable_source_file_refused(self):
        digest = elr_publish.publish_document("/no/such/path/does-not-exist.md", "Title")
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "source_file_unreadable")


# ---------------------------------------------------------------------------
# Dual-proof pass / independent proof failures
# ---------------------------------------------------------------------------


class DualProofPassTests(unittest.TestCase):
    def test_both_proofs_pass_full_happy_path(self):
        responses = [
            _sentinel_resp(),  # 1: plane-safety pre sentinel
            _count_probe_resp(),  # 2: plane-safety pre count probe
            _put_resp(),  # 3: documents.put
            _guard_resp(),  # 4: concurrency guard reread
            _patch_resp(),  # 5: documents.patch
            _reread_resp(),  # 6: verify-by-reread
            _post_probe_resp(),  # 7: plane-safety post target probe
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                    digest = elr_publish.publish_document(
                        source, "Title", related=["ENC-TSK-O54"], preserve_dir=f"{tmpdir}/preserved"
                    )

        self.assertTrue(digest["ok"])
        self.assertEqual(digest["document_id"], MINTED_ID)
        self.assertEqual(digest["proofs"], {"hash_echo": "pass", "reverse_substitution": "pass"})
        self.assertEqual(digest["source_sha256"], SOURCE_SHA256)
        self.assertEqual(digest["reverse_substituted_sha256"], SOURCE_SHA256)
        self.assertTrue(digest["patch_performed"])
        self.assertIn("compliance_score", digest)
        self.assertIn("plane_safety", digest)
        self.assertEqual(mock_urlopen.call_count, 7)
        # sent exactly one PATCH, never a second
        methods = [call.args[0].get_method() for call in mock_urlopen.call_args_list]
        self.assertEqual(methods.count("PATCH"), 1)
        self.assertEqual(methods.count("PUT"), 1)
        # digest never smuggles a raw body anywhere
        serialized = json.dumps(digest)
        self.assertNotIn("Body text used across", serialized)

    def test_hash_echo_proof_fails_independently_of_reverse_substitution(self):
        responses = [
            _sentinel_resp(),
            _count_probe_resp(),
            _put_resp(content_hash="0" * 64),  # PROOF 1 deliberately wrong
            _guard_resp(content_hash="0" * 64),  # guard must match PUT's (wrong) echo to avoid a false HALT
            _patch_resp(),
            _reread_resp(),  # stored content reverse-substitutes correctly -> PROOF 2 still passes
            _post_probe_resp(),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
                    digest = elr_publish.publish_document(source, "Title", preserve_dir=f"{tmpdir}/preserved")

        self.assertFalse(digest["ok"])
        self.assertEqual(digest["proofs"]["hash_echo"], "fail")
        self.assertEqual(digest["proofs"]["reverse_substitution"], "pass")
        self.assertIn("put-content-hash-mismatch", digest["anomalies"])

    def test_reverse_substitution_proof_fails_independently_of_hash_echo(self):
        corrupted_stored = _patched_content() + " CORRUPTED-EXTRA-TEXT-NOT-IN-SOURCE"
        responses = [
            _sentinel_resp(),
            _count_probe_resp(),
            _put_resp(),  # PROOF 1 correct
            _guard_resp(),
            _patch_resp(),
            _reread_resp(content=corrupted_stored),  # PROOF 2 deliberately wrong
            _post_probe_resp(),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
                    digest = elr_publish.publish_document(source, "Title", preserve_dir=f"{tmpdir}/preserved")

        self.assertFalse(digest["ok"])
        self.assertEqual(digest["proofs"]["hash_echo"], "pass")
        self.assertEqual(digest["proofs"]["reverse_substitution"], "fail")
        self.assertIn("reverse-substitution-hash-mismatch", digest["anomalies"])

    def test_placeholder_round_trip_reverse_substitution_matches_source(self):
        responses = [
            _sentinel_resp(),
            _count_probe_resp(),
            _put_resp(),
            _guard_resp(),
            _patch_resp(),
            _reread_resp(),
            _post_probe_resp(),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
                    digest = elr_publish.publish_document(source, "Title", preserve_dir=f"{tmpdir}/preserved")
        # Reconstructing with the minted id -> placeholder must reproduce the
        # exact original source hash (round trip proof).
        self.assertEqual(digest["reverse_substituted_sha256"], SOURCE_SHA256)


# ---------------------------------------------------------------------------
# Concurrency HALT
# ---------------------------------------------------------------------------


class ConcurrencyHaltTests(unittest.TestCase):
    def test_hash_mismatch_on_pre_patch_reread_halts_and_preserves(self):
        session_b_hash = "1" * 64  # session B's landed content_hash, different from ours
        responses = [
            _sentinel_resp(),
            _count_probe_resp(),
            _put_resp(),  # our put -- echoes SOURCE_SHA256
            _guard_resp(content_hash=session_b_hash),  # session B landed between put and patch
            _post_probe_resp(),  # plane-safety post probe still runs (the create landed)
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            preserve_dir = f"{tmpdir}/preserved"
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                    digest = elr_publish.publish_document(source, "Title", preserve_dir=preserve_dir)

            self.assertFalse(digest["ok"])
            self.assertEqual(digest["refusal"]["reason"], "concurrent-edit-detected")
            self.assertEqual(digest["document_id"], MINTED_ID)

            preserved_path = Path(digest["preserved_path"])
            self.assertTrue(preserved_path.is_file())
            self.assertEqual(preserved_path.read_text(encoding="utf-8"), _patched_content())

            # PATCH must NEVER have been called.
            methods = [call.args[0].get_method() for call in mock_urlopen.call_args_list]
            self.assertNotIn("PATCH", methods)
            self.assertEqual(mock_urlopen.call_count, 5)

    def test_unreachable_pre_patch_reread_also_halts(self):
        responses = [
            _sentinel_resp(),
            _count_probe_resp(),
            _put_resp(),
            _http_error(404, b'{"error":"not found"}'),  # guard reread itself fails
            _post_probe_resp(),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            preserve_dir = f"{tmpdir}/preserved"
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                    digest = elr_publish.publish_document(source, "Title", preserve_dir=preserve_dir)

        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "concurrency-guard-unreachable")
        methods = [call.args[0].get_method() for call in mock_urlopen.call_args_list]
        self.assertNotIn("PATCH", methods)


# ---------------------------------------------------------------------------
# Ambiguous patch echo
# ---------------------------------------------------------------------------


class AmbiguousEchoTests(unittest.TestCase):
    def test_ambiguous_5xx_patch_echo_recovers_via_reread_no_second_patch(self):
        responses = [
            _sentinel_resp(),
            _count_probe_resp(),
            _put_resp(),
            _guard_resp(),
            _http_error(504, b""),  # ambiguous: gateway timeout on the patch call itself
            _reread_resp(),  # but the write actually landed
            _post_probe_resp(),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                    digest = elr_publish.publish_document(source, "Title", preserve_dir=f"{tmpdir}/preserved")

        self.assertTrue(digest["ok"])
        self.assertIn("ambiguous-patch-echo", digest["anomalies"])
        self.assertIn("ambiguous-patch-echo-recovered-via-reread", digest["anomalies"])
        methods = [call.args[0].get_method() for call in mock_urlopen.call_args_list]
        self.assertEqual(methods.count("PATCH"), 1)

    def test_ambiguous_transport_failure_patch_echo_not_recovered(self):
        responses = [
            _sentinel_resp(),
            _count_probe_resp(),
            _put_resp(),
            _guard_resp(),
            urllib.error.URLError("connection reset"),  # status 0 -- ambiguous
            _reread_resp(content=SOURCE_TEXT),  # write did NOT actually land (still raw source)
            _post_probe_resp(),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                    digest = elr_publish.publish_document(source, "Title", preserve_dir=f"{tmpdir}/preserved")

        self.assertFalse(digest["ok"])
        self.assertIn("ambiguous-patch-echo", digest["anomalies"])
        self.assertIn("patch-did-not-apply-minted-id-absent", digest["anomalies"])
        self.assertEqual(digest["proofs"]["reverse_substitution"], "fail")
        # never falsely "recovered" -- the minted id genuinely never landed
        self.assertNotIn("ambiguous-patch-echo-recovered-via-reread", digest["anomalies"])
        methods = [call.args[0].get_method() for call in mock_urlopen.call_args_list]
        self.assertEqual(methods.count("PATCH"), 1)


# ---------------------------------------------------------------------------
# No placeholder in source
# ---------------------------------------------------------------------------


class NoPlaceholderTests(unittest.TestCase):
    def test_no_placeholder_skips_patch_entirely(self):
        plain_text = "# A plain document\n\nNo self-reference token here.\n"
        plain_bytes = plain_text.encode("utf-8")
        plain_sha = hashlib.sha256(plain_bytes).hexdigest()

        responses = [
            _sentinel_resp(),
            _count_probe_resp(),
            _put_resp(content_hash=plain_sha, size_bytes=len(plain_bytes)),
            _post_probe_resp(),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir, text=plain_text)
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                    digest = elr_publish.publish_document(source, "Title", preserve_dir=f"{tmpdir}/preserved")

        self.assertTrue(digest["ok"])
        self.assertFalse(digest["patch_performed"])
        self.assertEqual(digest["proofs"]["reverse_substitution"], "skip")
        self.assertIn("no-placeholder-in-source-patch-skipped", digest["anomalies"])
        self.assertEqual(mock_urlopen.call_count, 4)
        methods = [call.args[0].get_method() for call in mock_urlopen.call_args_list]
        self.assertNotIn("PATCH", methods)


# ---------------------------------------------------------------------------
# Plane-safety integration (sentinel abort + report shape)
# ---------------------------------------------------------------------------


class PlaneSafetyIntegrationTests(unittest.TestCase):
    def test_sentinel_mismatch_aborts_before_any_write(self):
        wrong_sentinel = _FakeHttpResponse(
            200, json.dumps(_doc_body({"document_id": "DOC-WRONGTWIN0001", "version": 1})).encode("utf-8")
        )
        responses = [wrong_sentinel, _count_probe_resp()]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                    digest = elr_publish.publish_document(source, "Title", preserve_dir=f"{tmpdir}/preserved")

        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "plane-safety-sentinel-mismatch")
        methods = [call.args[0].get_method() for call in mock_urlopen.call_args_list]
        self.assertNotIn("PUT", methods)
        self.assertEqual(mock_urlopen.call_count, 2)

    def test_plane_safety_report_shape_includes_degraded_plane_b(self):
        responses = [
            _sentinel_resp(),
            _count_probe_resp(),
            _put_resp(),
            _guard_resp(),
            _patch_resp(),
            _reread_resp(),
            _post_probe_resp(),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
                    digest = elr_publish.publish_document(source, "Title", preserve_dir=f"{tmpdir}/preserved")

        report = digest["plane_safety"]
        self.assertEqual(
            set(report["steps"].keys()),
            {"1_pre_state", "2_sentinel_identity", "3_write", "4_post_probe", "5_monotonic_id"},
        )
        self.assertIn("plane-b-probe-unconfigured", report["anomalies"])


# ---------------------------------------------------------------------------
# PUT failure
# ---------------------------------------------------------------------------


class PutFailureTests(unittest.TestCase):
    def test_put_rejected_never_attempts_patch(self):
        responses = [
            _sentinel_resp(),
            _count_probe_resp(),
            _http_error(400, b'{"error":"Field title is required."}'),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses) as mock_urlopen:
                    digest = elr_publish.publish_document(source, "Title", preserve_dir=f"{tmpdir}/preserved")

        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "put_failed")
        self.assertEqual(mock_urlopen.call_count, 3)


# ---------------------------------------------------------------------------
# Never prints bodies
# ---------------------------------------------------------------------------


class NoBodyOnStdoutTests(unittest.TestCase):
    def test_main_never_prints_source_body(self):
        responses = [
            _sentinel_resp(),
            _count_probe_resp(),
            _put_resp(),
            _guard_resp(),
            _patch_resp(),
            _reread_resp(),
            _post_probe_resp(),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source(tmpdir)
            stdout = io.StringIO()
            with _patched_preflight():
                with patch("elr_lib.transport.urllib.request.urlopen", side_effect=responses):
                    with contextlib.redirect_stdout(stdout):
                        exit_code = elr_publish.main(
                            [source, "--title", "Title", "--preserve-dir", f"{tmpdir}/preserved"]
                        )
        captured = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertNotIn("Body text used across", captured)
        lines = [line for line in captured.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertTrue(parsed["ok"])


if __name__ == "__main__":
    unittest.main()
