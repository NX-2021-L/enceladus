"""End-to-end integration tests for ENC-FTR-097 Manifest Primitive v1.

These tests exercise the actual handler functions in server.py against the
live tracker API. They are network-gated — set RUN_LIVE_MANIFEST=1 to run.

The wave-handoff scenario (ENC-FTR-097 AC4 / ENC-TSK-G41 AC3) is the
load-bearing case: 20 record IDs → tracker.manifest_bulk → tracker.get_acs
on the first incomplete AC.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))


def _live_enabled() -> bool:
    return os.environ.get("RUN_LIVE_MANIFEST", "").strip() in ("1", "true", "yes")


def _read_text(content_list) -> dict:
    """Unpack the FastMCP TextContent envelope back to a dict."""
    if not content_list:
        return {}
    payload = content_list[0]
    text = getattr(payload, "text", None) or (payload[1] if isinstance(payload, tuple) else None)
    if text is None and isinstance(payload, dict):
        text = payload.get("text")
    return json.loads(text) if text else {}


@unittest.skipUnless(_live_enabled(), "live integration disabled (set RUN_LIVE_MANIFEST=1)")
class ManifestLiveIntegrationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Lazy import — server.py pulls in the full FastMCP / Cognito stack
        # which is irrelevant for the unit-test suite.
        global server
        import server  # noqa: F401
        cls.server = server

    def _await(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_manifest_returns_content_hash(self):
        result = self._await(self.server._tracker_manifest({"record_id": "ENC-TSK-G27"}))
        payload = _read_text(result)
        self.assertIn("content_hash", payload)
        self.assertEqual(len(payload["content_hash"]), 64)
        self.assertEqual(payload["record_id"], "ENC-TSK-G27")
        self.assertGreaterEqual(payload["ac_count"], 1)

    def test_get_acs_freshness_contract_rejects_stale_hash(self):
        result = self._await(self.server._tracker_get_acs({
            "record_id": "ENC-TSK-G27",
            "indices": [0],
            "content_hash": "0" * 64,
        }))
        payload = _read_text(result)
        self.assertTrue(payload.get("error"))
        self.assertEqual(payload.get("error_code"), "STALE_CONTENT_HASH")

    def test_wave_handoff_resume_workflow(self):
        """20-record handoff manifest_bulk → first incomplete AC fetch."""
        record_ids = [
            f"ENC-TSK-G{n:02d}" for n in range(27, 47)  # G27..G46
        ]
        result = self._await(self.server._tracker_manifest_bulk({"record_ids": record_ids}))
        payload = _read_text(result)
        self.assertGreaterEqual(payload.get("manifest_count", 0), 1)

        # Identify the first incomplete AC across the bulk response.
        target_record_id = None
        target_index = None
        target_hash = None
        for entry in payload["manifests"]:
            for ac in entry["manifest"].get("acs", []):
                if ac.get("status") == "incomplete":
                    target_record_id = entry["record_id"]
                    target_index = ac["ac_index"]
                    target_hash = entry["content_hash"]
                    break
            if target_record_id is not None:
                break
        self.assertIsNotNone(target_record_id, "expected at least one incomplete AC")

        # Fetch the AC body with a valid content_hash — the freshness contract
        # accepts the call.
        ac_result = self._await(self.server._tracker_get_acs({
            "record_id": target_record_id,
            "indices": [target_index],
            "content_hash": target_hash,
        }))
        ac_payload = _read_text(ac_result)
        self.assertNotIn("error", ac_payload)
        self.assertEqual(ac_payload["acs"][0]["ac_index"], target_index)


if __name__ == "__main__":
    unittest.main()
