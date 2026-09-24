"""Tests for anthropic_batch module (ENC-TSK-G19)."""
from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

import anthropic_batch as ab


class AnthropicBatchModuleTests(unittest.TestCase):
    def test_non_interactive_workloads_enumerated(self):
        self.assertIn("nightly_changelog_generation", ab.NON_INTERACTIVE_WORKLOADS)
        self.assertIn("governance_audit_doc_patching", ab.NON_INTERACTIVE_WORKLOADS)
        self.assertGreaterEqual(len(ab.NON_INTERACTIVE_WORKLOADS), 4)

    def test_batch_poll_interval_is_60_seconds(self):
        self.assertEqual(ab.BATCH_POLL_INTERVAL_SECONDS, 60)

    def test_batch_processing_ended(self):
        self.assertTrue(ab.batch_processing_ended({"processing_status": "ended"}))
        self.assertFalse(ab.batch_processing_ended({"processing_status": "in_progress"}))

    def test_submit_messages_batch_success(self):
        payload = {"id": "batch_abc", "processing_status": "in_progress"}
        with patch.object(ab, "anthropic_http_json", return_value=(200, payload, {})):
            out = ab.submit_messages_batch(
                api_key="sk-test",
                requests=[{"custom_id": "d1", "params": {"model": "claude", "max_tokens": 100, "messages": []}}],
            )
        self.assertEqual(out["id"], "batch_abc")

    def test_submit_messages_batch_raises_on_error(self):
        with patch.object(
            ab,
            "anthropic_http_json",
            return_value=(200, {"error": {"type": "invalid", "message": "bad"}}, {}),
        ):
            with self.assertRaises(RuntimeError):
                ab.submit_messages_batch(api_key="sk-test", requests=[])

    def test_alert_batch_subrequest_failure_emits_observability(self):
        emit = MagicMock()
        ab.alert_batch_subrequest_failure(
            emit,
            request_id="CRQ-1",
            dispatch_id="DISP-1",
            batch_id="batch_abc",
            custom_id="DISP-1",
            error_type="rate_limit",
            error_message="too many",
        )
        emit.assert_called_once()
        kwargs = emit.call_args.kwargs
        self.assertEqual(kwargs["event"], "batch_subrequest_failure")
        self.assertEqual(kwargs["error_code"], "batch_subrequest_failed")
        self.assertTrue(kwargs["extra"]["alert"])

    def test_cost_comparison_documented(self):
        cmp_doc = ab.NIGHTLY_CHANGELOG_COST_COMPARISON
        self.assertEqual(cmp_doc["workload"], "nightly_changelog_generation")
        self.assertGreater(cmp_doc["effective_reduction_pct"], 50)


if __name__ == "__main__":
    unittest.main()
