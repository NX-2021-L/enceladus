"""Unit tests for identity (ENC-TSK-N21 / BRD DOC-44230223DD1C §4.3)."""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import identity  # noqa: E402


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


class ResolveIdentityConfigGateTests(unittest.TestCase):
    @mock.patch.object(identity, "COORDINATION_API_BASE", "")
    def test_degraded_when_coordination_api_unconfigured(self):
        result = identity.resolve_identity()
        self.assertTrue(result["degraded"])
        self.assertEqual(result["session_id"], "")
        self.assertEqual(result["sci"], "")

    @mock.patch.object(identity, "RHYTHM_AGENT_TYPE_ID", "")
    @mock.patch.object(identity, "COORDINATION_API_BASE", "https://x/api/v1")
    def test_degraded_when_agent_type_unset(self):
        result = identity.resolve_identity()
        self.assertTrue(result["degraded"])
        self.assertIn("RHYTHM_AGENT_TYPE_ID", result["reason"])


class ResolveIdentityMintTests(unittest.TestCase):
    @mock.patch.object(identity, "COORDINATION_API_BASE", "https://x/api/v1")
    @mock.patch.object(identity, "RHYTHM_AGENT_TYPE_ID", "ENC-AGT-00C")
    @mock.patch.object(identity, "write_artifact")
    @mock.patch.object(identity, "post_json")
    @mock.patch.object(identity, "read_latest", return_value=None)
    def test_mints_new_identity_when_no_cache(self, _read_latest, post_json, write_artifact):
        post_json.side_effect = [
            {"session": {"session_id": "ENC-SES-099"}},
            {"sci": "SCI-abc123", "sci_issued_at": _iso(datetime.now(timezone.utc)), "sci_ttl_seconds": 86400},
        ]
        result = identity.resolve_identity()

        self.assertFalse(result["degraded"])
        self.assertEqual(result["session_id"], "ENC-SES-099")
        self.assertEqual(result["sci"], "SCI-abc123")
        register_call, claim_call = post_json.call_args_list
        self.assertEqual(register_call.args[0], "https://x/api/v1/coordination/agents/sessions")
        self.assertEqual(register_call.args[1]["agent_type_id"], "ENC-AGT-00C")
        self.assertEqual(claim_call.args[0], "https://x/api/v1/coordination/agents/sessions/claim")
        self.assertEqual(claim_call.args[1]["session_id"], "ENC-SES-099")
        write_artifact.assert_called_once()
        self.assertEqual(write_artifact.call_args.args[0], "identity")

    @mock.patch.object(identity, "COORDINATION_API_BASE", "https://x/api/v1")
    @mock.patch.object(identity, "RHYTHM_AGENT_TYPE_ID", "ENC-AGT-00C")
    @mock.patch.object(identity, "write_artifact")
    @mock.patch.object(identity, "post_json")
    def test_uses_cached_identity_when_sci_not_expired(self, post_json, _write_artifact):
        cached = {
            "session_id": "ENC-SES-100",
            "agent_type_id": "ENC-AGT-00C",
            "sci": "SCI-cached",
            "sci_issued_at": _iso(datetime.now(timezone.utc) - timedelta(hours=1)),
            "sci_ttl_seconds": 86400,
            "degraded": False,
        }
        with mock.patch.object(identity, "read_latest", return_value=cached):
            result = identity.resolve_identity()

        self.assertEqual(result, cached)
        post_json.assert_not_called()

    @mock.patch.object(identity, "COORDINATION_API_BASE", "https://x/api/v1")
    @mock.patch.object(identity, "RHYTHM_AGENT_TYPE_ID", "ENC-AGT-00C")
    @mock.patch.object(identity, "write_artifact")
    @mock.patch.object(identity, "post_json")
    def test_reclaims_when_sci_close_to_ttl_expiry(self, post_json, write_artifact):
        cached = {
            "session_id": "ENC-SES-101",
            "agent_type_id": "ENC-AGT-00C",
            "sci": "SCI-stale",
            # issued nearly a full TTL ago — inside the renew skew window.
            "sci_issued_at": _iso(datetime.now(timezone.utc) - timedelta(seconds=86400 - 60)),
            "sci_ttl_seconds": 86400,
            "degraded": False,
        }
        post_json.return_value = {
            "sci": "SCI-fresh",
            "sci_issued_at": _iso(datetime.now(timezone.utc)),
            "sci_ttl_seconds": 86400,
        }
        with mock.patch.object(identity, "read_latest", return_value=cached):
            result = identity.resolve_identity()

        self.assertFalse(result["degraded"])
        self.assertEqual(result["session_id"], "ENC-SES-101")
        self.assertEqual(result["sci"], "SCI-fresh")
        # Only the claim endpoint is hit on re-claim — no re-register.
        post_json.assert_called_once()
        self.assertEqual(
            post_json.call_args.args[0], "https://x/api/v1/coordination/agents/sessions/claim"
        )
        write_artifact.assert_called_once()

    @mock.patch.object(identity, "COORDINATION_API_BASE", "https://x/api/v1")
    @mock.patch.object(identity, "RHYTHM_AGENT_TYPE_ID", "ENC-AGT-00C")
    @mock.patch.object(identity, "write_artifact")
    @mock.patch.object(identity, "post_json")
    def test_degraded_on_http_failure_never_raises_and_keeps_prior_session_id(
        self, post_json, write_artifact
    ):
        cached = {
            "session_id": "ENC-SES-102",
            "sci_issued_at": _iso(datetime.now(timezone.utc) - timedelta(seconds=86400)),
            "sci_ttl_seconds": 86400,
        }
        post_json.side_effect = RuntimeError("HTTP 500 from claim endpoint")
        with mock.patch.object(identity, "read_latest", return_value=cached):
            result = identity.resolve_identity()  # must not raise

        self.assertTrue(result["degraded"])
        self.assertEqual(result["session_id"], "ENC-SES-102")
        self.assertEqual(result["sci"], "")
        write_artifact.assert_not_called()

    @mock.patch.object(identity, "COORDINATION_API_BASE", "https://x/api/v1")
    @mock.patch.object(identity, "RHYTHM_AGENT_TYPE_ID", "ENC-AGT-00C")
    @mock.patch.object(identity, "write_artifact")
    @mock.patch.object(identity, "post_json")
    @mock.patch.object(identity, "read_latest", return_value=None)
    def test_degraded_when_register_returns_no_session_id(self, _read_latest, post_json, write_artifact):
        post_json.return_value = {"session": {}}
        result = identity.resolve_identity()
        self.assertTrue(result["degraded"])
        write_artifact.assert_not_called()


if __name__ == "__main__":
    unittest.main()
