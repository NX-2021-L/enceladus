"""tools/test_docstore_race_harness.py — cheap mocked-transport unit tests for
the ENC-TSK-P70 AC-5 race harness (tools/docstore_race_harness.py).

No real network calls: `_request` is monkeypatched to a fake transport that
simulates the document_api behavior (one 200 winner, the rest 412) so the
harness's own trial/evaluation logic can be verified in CI. The actual
concurrent-race proof against a live deployment is out of scope for this
process-local test — that's what the script's real run against gamma (via
--base-url) is for, executed by the coordinator post-deploy.

Run: python3 -m pytest tools/test_docstore_race_harness.py -v
"""

from __future__ import annotations

import itertools
import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(__file__))

import docstore_race_harness as harness  # noqa: E402


class TestEvaluateTrial(unittest.TestCase):
    def test_two_writers_one_success_one_failure_passes(self):
        self.assertTrue(harness.evaluate_trial([200, 412], writers=2))
        self.assertTrue(harness.evaluate_trial([412, 200], writers=2))

    def test_three_writers_one_success_two_failures_passes(self):
        self.assertTrue(harness.evaluate_trial([200, 412, 412], writers=3))

    def test_two_successes_fails(self):
        self.assertFalse(harness.evaluate_trial([200, 200], writers=2))

    def test_zero_successes_fails(self):
        self.assertFalse(harness.evaluate_trial([412, 412], writers=2))

    def test_unexpected_status_fails(self):
        self.assertFalse(harness.evaluate_trial([200, 500], writers=2))
        self.assertFalse(harness.evaluate_trial([200, 0], writers=2))


class TestRunTrialWithFakeTransport(unittest.TestCase):
    """Simulates the document_api race outcome (exactly one writer wins) without
    any real HTTP call, by faking `_request` to return 200 for the first PATCH
    to acquire a lock and 412 for every subsequent one."""

    def test_run_trial_two_writers_exactly_one_winner(self):
        lock_holder = {"taken": False}
        call_lock = __import__("threading").Lock()

        def fake_request(method, url, api_key, body=None, extra_headers=None, timeout=15.0):
            if method == "PATCH":
                with call_lock:
                    if not lock_holder["taken"]:
                        lock_holder["taken"] = True
                        return 200, {"success": True}
                    return 412, {"error_envelope": {"code": "CONTENT_HASH_MISMATCH"}}
            raise AssertionError(f"unexpected method {method}")

        with patch.object(harness, "_request", side_effect=fake_request):
            statuses = harness.run_trial(
                "https://example.invalid/api/v1/documents", "fake-key",
                "DOC-FAKE0001", "a" * 64, writers=2,
            )
        self.assertTrue(harness.evaluate_trial(statuses, writers=2))
        self.assertEqual(sorted(statuses), [200, 412])

    def test_run_trial_three_writers_exactly_one_winner(self):
        lock_holder = {"taken": False}
        call_lock = __import__("threading").Lock()

        def fake_request(method, url, api_key, body=None, extra_headers=None, timeout=15.0):
            with call_lock:
                if not lock_holder["taken"]:
                    lock_holder["taken"] = True
                    return 200, {"success": True}
                return 412, {"error_envelope": {"code": "CONTENT_HASH_MISMATCH"}}

        with patch.object(harness, "_request", side_effect=fake_request):
            statuses = harness.run_trial(
                "https://example.invalid/api/v1/documents", "fake-key",
                "DOC-FAKE0002", "b" * 64, writers=3,
            )
        self.assertTrue(harness.evaluate_trial(statuses, writers=3))
        self.assertEqual(sorted(statuses), [200, 412, 412])


class TestCreateScratchDocument(unittest.TestCase):
    def test_parses_document_id_and_content_hash(self):
        def fake_request(method, url, api_key, body=None, extra_headers=None, timeout=15.0):
            self.assertEqual(method, "POST")
            self.assertTrue(body["title"].startswith(harness.SCRATCH_TITLE_PREFIX))
            return 200, {"success": True, "document_id": "DOC-ABC123", "content_hash": "c" * 64}

        with patch.object(harness, "_request", side_effect=fake_request):
            doc_id, content_hash = harness.create_scratch_document(
                "https://example.invalid/api/v1/documents", "fake-key", "enceladus",
            )
        self.assertEqual(doc_id, "DOC-ABC123")
        self.assertEqual(content_hash, "c" * 64)

    def test_missing_fields_raises(self):
        with patch.object(harness, "_request", return_value=(200, {"success": True})):
            with self.assertRaises(RuntimeError):
                harness.create_scratch_document(
                    "https://example.invalid/api/v1/documents", "fake-key", "enceladus",
                )

    def test_non_2xx_raises(self):
        with patch.object(harness, "_request", return_value=(500, {"error": "boom"})):
            with self.assertRaises(RuntimeError):
                harness.create_scratch_document(
                    "https://example.invalid/api/v1/documents", "fake-key", "enceladus",
                )


class TestRunHarnessAggregation(unittest.TestCase):
    def test_all_passed_summary(self):
        counter = itertools.count()

        def fake_create(base_url, api_key, project_id):
            n = next(counter)
            return f"DOC-{n:04d}", "d" * 64

        def fake_run_trial(base_url, api_key, document_id, if_match, writers):
            return [200] + [412] * (writers - 1)

        with patch.object(harness, "create_scratch_document", side_effect=fake_create), \
             patch.object(harness, "run_trial", side_effect=fake_run_trial):
            summary = harness.run_harness(
                "https://example.invalid/api/v1/documents", "enceladus",
                trials=5, writers=2, api_key="fake-key",
            )
        self.assertTrue(summary["all_passed"])
        self.assertEqual(summary["trials_passed"], 5)
        self.assertEqual(summary["trials_failed"], 0)
        # Never leaks the key into the summary.
        self.assertNotIn("fake-key", json.dumps(summary))

    def test_one_bad_trial_flagged_and_not_all_passed(self):
        counter = itertools.count()

        def fake_create(base_url, api_key, project_id):
            n = next(counter)
            return f"DOC-{n:04d}", "e" * 64

        def fake_run_trial(base_url, api_key, document_id, if_match, writers):
            # Second trial simulates a bug: both writers succeed.
            if document_id == "DOC-0001":
                return [200, 200]
            return [200, 412]

        with patch.object(harness, "create_scratch_document", side_effect=fake_create), \
             patch.object(harness, "run_trial", side_effect=fake_run_trial):
            summary = harness.run_harness(
                "https://example.invalid/api/v1/documents", "enceladus",
                trials=3, writers=2, api_key="fake-key",
            )
        self.assertFalse(summary["all_passed"])
        self.assertEqual(summary["trials_failed"], 1)
        self.assertEqual(summary["failures"][0]["document_id"], "DOC-0001")


class TestMainArgValidation(unittest.TestCase):
    def test_missing_api_key_env_returns_1_and_never_hangs(self):
        env = dict(os.environ)
        env.pop(harness.ENV_KEY_NAME, None)
        with patch.dict(os.environ, env, clear=True):
            rc = harness.main(["--base-url", "https://example.invalid/api/v1/documents"])
        self.assertEqual(rc, 1)

    def test_writers_below_two_rejected(self):
        with patch.dict(os.environ, {harness.ENV_KEY_NAME: "fake-key"}):
            rc = harness.main([
                "--base-url", "https://example.invalid/api/v1/documents", "--writers", "1",
            ])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
