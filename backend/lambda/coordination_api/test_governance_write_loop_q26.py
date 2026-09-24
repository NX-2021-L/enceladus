"""ENC-TSK-Q26 — the governance write path must close its own loop.

Covers ENC-ISS-800 (a non-ASCII change_summary must not abort the write),
ENC-ISS-799 (every governance object must carry the SHA256 additional checksum the
bundle-root recompute hard-requires, the receipt must not present a known-stale hash
as post-write truth, and the recompute must be nudged rather than left to the hourly
backstop), and the ENC-ISS-798 reclassification (the dictionary is deploy-coupled, so
the served source stays "bundled" by design).
"""

import importlib.util
import json
import pathlib
import sys
import unittest
from unittest.mock import MagicMock, patch

MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("coordination_lambda_q26", MODULE_PATH)
coordination_lambda = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = coordination_lambda
SPEC.loader.exec_module(coordination_lambda)

PRECONDITION_HASH = "a" * 64


def _event(change_summary: str = "plain ascii summary", content: str = "# agents\n") -> dict:
    return {
        "rawPath": "/api/v1/governance/agents.md",
        "body": json.dumps({
            "file_name": "agents.md",
            "content": content,
            "change_summary": change_summary,
            "governance_hash": PRECONDITION_HASH,
        }),
    }


class S3MetadataSafeTests(unittest.TestCase):
    """ENC-ISS-800: the sanitizer itself."""

    def test_section_sign_is_transliterated_not_dropped(self):
        out = coordination_lambda._s3_metadata_safe("ENC-TSK-Q26 §13 lockstep bump")
        self.assertTrue(out.isascii())
        self.assertIn("section 13", out)
        self.assertNotIn("§", out)

    def test_common_typography_is_reduced_to_ascii(self):
        out = coordination_lambda._s3_metadata_safe(
            "em—dash ‘quote’ “dquote” ellipsis… arrow→ nbsp here"
        )
        self.assertTrue(out.isascii())
        for ch in ("—", "‘", "’", "“", "”", "…", "→", " "):
            self.assertNotIn(ch, out)

    def test_arbitrary_non_ascii_is_stripped_and_result_is_ascii(self):
        out = coordination_lambda._s3_metadata_safe("emoji \U0001f600 kanji 漢字 accents café")
        self.assertTrue(out.isascii())

    def test_newlines_and_control_chars_are_collapsed(self):
        out = coordination_lambda._s3_metadata_safe("line one\nline two\r\n\tline three")
        self.assertTrue(out.isascii())
        self.assertNotIn("\n", out)
        self.assertNotIn("\r", out)
        self.assertNotIn("\t", out)
        self.assertEqual(out, "line one line two line three")

    def test_truncation_is_bounded_and_byte_safe(self):
        # A multi-byte-heavy input must still truncate to a pure-ASCII value at the
        # limit: sanitising before slicing is what makes the bound byte-safe.
        out = coordination_lambda._s3_metadata_safe("§" * 500, limit=64)
        self.assertEqual(len(out), 64)
        self.assertTrue(out.isascii())
        self.assertEqual(len(out.encode("utf-8")), 64)

    def test_empty_input_is_empty_output(self):
        self.assertEqual(coordination_lambda._s3_metadata_safe(""), "")


class GovernanceUpdateWritePathTests(unittest.TestCase):
    """ENC-ISS-799 + ENC-ISS-800 through the real handler."""

    def setUp(self):
        self.s3 = MagicMock()
        # No existing object -> exercise the live-write path; archival is covered separately.
        self.s3.exceptions.NoSuchKey = type("NoSuchKey", (Exception,), {})
        self.s3.get_object.side_effect = self.s3.exceptions.NoSuchKey()
        self.lambda_client = MagicMock()

    def _run(self, event):
        with patch.object(coordination_lambda, "_get_s3", return_value=self.s3), \
             patch.object(coordination_lambda, "_get_lambda_client", return_value=self.lambda_client), \
             patch.object(coordination_lambda, "_trigger_governance_doc_sync_push"), \
             patch.object(coordination_lambda, "_compute_governance_hash_local",
                          return_value=PRECONDITION_HASH):
            return coordination_lambda._handle_governance_update(event)

    def test_live_write_carries_sha256_additional_checksum(self):
        # ENC-ISS-799 root cause: without this, devops-recompute-governance raises
        # "No ChecksumSHA256 on ..." and freezes the bundle root for EVERY file.
        resp = self._run(_event())
        self.assertEqual(resp["statusCode"], 200)
        self.assertTrue(self.s3.put_object.called)
        for call in self.s3.put_object.call_args_list:
            self.assertEqual(call.kwargs.get("ChecksumAlgorithm"), "SHA256")

    def test_archive_write_also_carries_the_checksum(self):
        existing = MagicMock()
        existing.__getitem__ = lambda _self, key: MagicMock(read=lambda: b"# previous\n")
        self.s3.get_object.side_effect = None
        self.s3.get_object.return_value = {"Body": MagicMock(read=lambda: b"# previous\n")}
        resp = self._run(_event())
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(self.s3.put_object.call_count, 2)  # archive + live
        for call in self.s3.put_object.call_args_list:
            self.assertEqual(call.kwargs.get("ChecksumAlgorithm"), "SHA256")

    def test_non_ascii_change_summary_no_longer_aborts_the_write(self):
        # Regression for the exact failure seen in prod: a literal section sign in a
        # §13 summary aborted archival with an opaque HTTP 500.
        resp = self._run(_event(change_summary="ENC-TSK-Q23 §13 lockstep bump — live"))
        self.assertEqual(resp["statusCode"], 200)
        for call in self.s3.put_object.call_args_list:
            summary = call.kwargs["Metadata"]["change_summary"]
            self.assertTrue(summary.isascii(), summary)
            self.assertLessEqual(len(summary.encode("utf-8")), 256)

    def test_receipt_flags_the_canonical_hash_as_pending(self):
        # The canonical record is written BY the recompute, so reading it microseconds
        # after our own put necessarily returns the pre-write value.
        resp = self._run(_event())
        payload = json.loads(resp["body"])
        self.assertTrue(payload["governance_hash_pending"])
        self.assertEqual(payload["canonical_recompute_backstop_seconds"], 3600)
        self.assertIn("content_hash", payload)
        self.assertNotEqual(payload["content_hash"], payload["governance_hash"])
        self.assertIn("drift", payload["governance_hash_note"])

    def test_receipt_clears_pending_once_canonical_has_moved(self):
        with patch.object(coordination_lambda, "_get_s3", return_value=self.s3), \
             patch.object(coordination_lambda, "_get_lambda_client", return_value=self.lambda_client), \
             patch.object(coordination_lambda, "_trigger_governance_doc_sync_push"), \
             patch.object(coordination_lambda, "_compute_governance_hash_local",
                          return_value="b" * 64):
            resp = coordination_lambda._handle_governance_update(_event())
        payload = json.loads(resp["body"])
        self.assertFalse(payload["governance_hash_pending"])
        self.assertEqual(payload["governance_hash"], "b" * 64)

    def test_recompute_is_nudged_with_a_backstop_shaped_payload(self):
        self._run(_event())
        self.assertTrue(self.lambda_client.invoke.called)
        kwargs = self.lambda_client.invoke.call_args.kwargs
        self.assertEqual(kwargs["InvocationType"], "Event")
        sent = json.loads(kwargs["Payload"].decode("utf-8"))
        # Must satisfy the recompute's own _extract_s3_record contract.
        self.assertEqual(
            sent["Records"][0]["s3"]["object"]["key"], "governance/live/agents.md"
        )

    def test_failed_recompute_nudge_does_not_fail_the_write(self):
        self.lambda_client.invoke.side_effect = RuntimeError("AccessDeniedException")
        resp = self._run(_event())
        self.assertEqual(resp["statusCode"], 200)


class GovernanceDictionaryIsDeployCoupledTests(unittest.TestCase):
    """ENC-ISS-798 reclassification: 'bundled' is the designed answer, not a bug."""

    def test_dictionary_source_is_bundled_by_design(self):
        _dictionary, meta = coordination_lambda._load_governance_dictionary()
        self.assertEqual(meta["source"], "bundled")
        self.assertTrue(meta["version"])


if __name__ == "__main__":
    unittest.main()
