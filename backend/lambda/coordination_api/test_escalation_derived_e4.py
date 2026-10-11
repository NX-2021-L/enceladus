"""ENC-TSK-967 (DVP-PLN-013 E4-W1.2, phase 2b): paused approvals and stale locks as derived gate cards.

A READ-TIME PROJECTION of the home requires-io queue through the escalations
feed: kinds tool_call and stale_lock, derived=true, F-10 expiry backfilled.
Opt-in, so the default feed neither calls GitHub nor changes shape (D9).
"""
import datetime as dt
import json
import unittest
from unittest import mock

from test_escalation_gate_e4 import COGNITO_CLAIMS, INTERNAL_CLAIMS, coord

NOW = dt.datetime(2026, 10, 11, 12, 0, 0, tzinfo=dt.timezone.utc)
RUNS = [
    {"id": 7001, "run_url": "https://example.test/runs/7001", "requesting_workflow": "promote-gamma-to-prod",
     "environments": ["v3-prod"], "head_sha": "abc123", "created_at": "2026-10-10T12:00:00Z"},
    {"id": 7002, "run_url": "https://example.test/runs/7002", "requesting_workflow": "promote-gamma-to-prod",
     "environments": ["v3-prod"], "head_sha": "def456", "created_at": "2026-10-01T00:00:00Z"},  # >72h old
]
LOCKS = [{"record_id": "DVP-TSK-900", "holder_session": "ENC-SES-0AA",
          "held_since": "2026-09-01T00:00:00Z", "age_minutes": 60000}]


class TestDerivedGateCards(unittest.TestCase):
    def _feed(self, params, runs=RUNS, locks=LOCKS, paused_status=200, claims=COGNITO_CLAIMS):
        ddb = mock.MagicMock()
        ddb.query.return_value = {"Items": []}
        paused = mock.Mock(return_value=coord._response(paused_status, {"success": True, "runs": runs}))
        stale = mock.Mock(return_value=coord._response(200, {"success": True, "locks": locks}))
        with mock.patch.object(coord, "_get_ddb", return_value=ddb), \
             mock.patch.object(coord, "_gate_now", return_value=NOW), \
             mock.patch.object(coord, "_handle_queue_paused_approvals", paused), \
             mock.patch.object(coord, "_handle_queue_stale_locks", stale):
            resp = coord._handle_escalations_feed({"queryStringParameters": params}, claims)
        return resp, paused, stale

    def _cards(self, params, **kw):
        resp, _, _ = self._feed(params, **kw)
        self.assertEqual(200, resp["statusCode"], resp["body"])
        body = json.loads(resp["body"])
        return body, {c["id"]: c for c in body["pending"] + body["terminal"]}

    def test_default_feed_is_unchanged_and_never_calls_the_queue_sources(self):
        resp, paused, stale = self._feed(None)
        body = json.loads(resp["body"])
        self.assertEqual((0, [], []), (body["count"], body["pending"], body["terminal"]))
        self.assertNotIn("derived_errors", body)
        paused.assert_not_called()
        stale.assert_not_called()

    def test_paused_approvals_read_back_as_tool_call_with_backfilled_expiry(self):
        body, cards = self._cards({"kind": "tool_call"})
        live, old = cards["DRV-PA-7001"], cards["DRV-PA-7002"]
        self.assertEqual(("tool_call", "decision", True), (live["kind"], live["family"], live["derived"]))
        self.assertEqual("2026-10-13T12:00:00Z", live["expiresAt"])  # created_at + 72h
        self.assertEqual(("pending", "deny"), (live["state"], live["onExpire"]))
        self.assertNotIn("diff", live)
        self.assertEqual("abc123", live["subject"]["version"])
        self.assertEqual("expired", old["state"])  # past its window: fail-closed
        self.assertIn(live, body["pending"])
        self.assertIn(old, body["terminal"])
        self.assertNotIn("DRV-SL-DVP-TSK-900", cards)  # kind filter honoured

    def test_stale_locks_read_back_as_stale_lock_regenerated_each_read(self):
        _, cards = self._cards({"kind": "stale_lock"})
        lock = cards["DRV-SL-DVP-TSK-900"]
        self.assertEqual(("stale_lock", "decision", True), (lock["kind"], lock["family"], lock["derived"]))
        self.assertEqual("2026-10-18T12:00:00Z", lock["expiresAt"])  # detection + 7d
        self.assertEqual(("pending", "regenerate", "low"), (lock["state"], lock["onExpire"], lock["risk"]))
        self.assertEqual(60000, lock["ageMinutes"])
        self.assertEqual("DVP-TSK-900", lock["evidence"][0]["ref"])

    def test_include_derived_adds_both_kinds_and_state_filter_applies(self):
        _, cards = self._cards({"include_derived": "true", "state": "pending"})
        self.assertEqual({"DRV-PA-7001", "DRV-SL-DVP-TSK-900"}, set(cards))

    def test_a_failing_source_degrades_the_feed_without_failing_it(self):
        body, cards = self._cards({"kind": "tool_call,stale_lock"}, paused_status=502)
        self.assertEqual(["paused_approvals_unavailable"], body["derived_errors"])
        self.assertEqual({"DRV-SL-DVP-TSK-900"}, set(cards))

    def test_machine_principals_remain_refused(self):
        resp, paused, _ = self._feed({"kind": "tool_call"}, claims=INTERNAL_CLAIMS)
        self.assertEqual(403, resp["statusCode"])
        paused.assert_not_called()


if __name__ == "__main__":
    unittest.main()
