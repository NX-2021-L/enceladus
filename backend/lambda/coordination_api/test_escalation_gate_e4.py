"""ENC-TSK-967 (DVP-PLN-013 E4-W1.2, phase 1): coordination-side gate behaviour.

Fail-closed expiry on decide (approve AND deny; no applier call, no write),
auth still ordered before expiry, and the cross-project feed with state/kind
filters (ENC-ISS-773 at the API) with the default single-project shape intact.
"""
import datetime as dt
import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

from test_escalation_decision_j70 import (  # noqa: E402
    COGNITO_CLAIMS, INTERNAL_CLAIMS, _decision_event, _escalation_item, _fake_ddb,
    _serialized, _target_item,
)

_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda_e4_gate", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
coord = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = coord
_SPEC.loader.exec_module(coord)

UTC = dt.timezone.utc
CREATED = dt.datetime(2026, 7, 2, 4, 0, 0, tzinfo=UTC)  # fixture created_at
INSIDE = CREATED + dt.timedelta(hours=1)
PAST_72H = CREATED + dt.timedelta(hours=72)


def _z(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


class TestDecideFailClosedExpiry(unittest.TestCase):
    def _decide(self, decision, escalation, now, claims=None):
        ddb = _fake_ddb(escalation=escalation, target=_target_item())
        invoke = mock.MagicMock(return_value={"success": True, "status": "applied", "_status_code": 200})
        with mock.patch.object(coord, "_get_ddb", return_value=ddb), \
             mock.patch.object(coord, "_gate_now", return_value=now), \
             mock.patch.object(coord, "_invoke_tracker_mutation_api", invoke), \
             mock.patch.object(coord, "_load_escalation_approver_allowlist", return_value={"io@jreese.net"}):
            caller = dict(claims or COGNITO_CLAIMS, auth_time=int(now.timestamp()) - 60)
            resp = coord._handle_escalation_decision(
                "enceladus", "ENC-ESC-001", decision, _decision_event({"guidance_note": "n"}, caller),
                caller)
        return resp, ddb, invoke

    def test_expired_legacy_escalation_cannot_be_approved(self):
        resp, ddb, invoke = self._decide("approve", _escalation_item(), PAST_72H)
        self.assertEqual(410, resp["statusCode"])
        body = json.loads(resp["body"])
        self.assertEqual("expired", body["state"])
        self.assertEqual("2026-07-05T04:00:00Z", body["expiresAt"])
        ddb.update_item.assert_not_called()   # no status write
        invoke.assert_not_called()            # no applier call

    def test_expired_legacy_escalation_cannot_be_denied_either(self):
        resp, ddb, invoke = self._decide("deny", _escalation_item(), PAST_72H)
        self.assertEqual(410, resp["statusCode"])
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()

    def test_one_second_before_expiry_is_still_decidable(self):
        resp, ddb, invoke = self._decide(
            "approve", _escalation_item(), PAST_72H - dt.timedelta(seconds=1))
        self.assertEqual(200, resp["statusCode"], resp["body"])
        invoke.assert_called_once()

    def test_explicit_stored_expiry_wins_over_default(self):
        short = dict(_escalation_item(), expiresAt=_z(CREATED + dt.timedelta(hours=2)))
        self.assertEqual(200, self._decide("approve", short, INSIDE)[0]["statusCode"])
        resp, ddb, invoke = self._decide("approve", short, CREATED + dt.timedelta(hours=2))
        self.assertEqual(410, resp["statusCode"])
        invoke.assert_not_called()

    def test_regenerate_kind_reports_superseded(self):
        lock = dict(_escalation_item(), kind="stale_lock")
        resp, _ddb, _inv = self._decide("approve", lock, CREATED + dt.timedelta(days=7))
        self.assertEqual(410, resp["statusCode"])
        self.assertEqual("superseded", json.loads(resp["body"])["state"])

    def test_auth_is_checked_before_expiry(self):
        resp, ddb, invoke = self._decide("approve", _escalation_item(), PAST_72H, claims=INTERNAL_CLAIMS)
        self.assertEqual(403, resp["statusCode"])  # not 410: decide stays unreachable to non-humans
        invoke.assert_not_called()

    def test_each_f10_default_boundary(self):
        for kind, ttl in (("acceptance", dt.timedelta(days=7)), ("reconciliation", dt.timedelta(days=7)),
                          ("stale_lock", dt.timedelta(days=7)), ("escalation", dt.timedelta(hours=72)),
                          ("tool_call", dt.timedelta(hours=72)), ("security", dt.timedelta(hours=72)),
                          ("limit", dt.timedelta(hours=24))):
            rec = {"kind": kind, "created_at": _z(CREATED)}
            with self.subTest(kind=kind):
                self.assertFalse(coord._escalation_expiry_info(rec, CREATED + ttl - dt.timedelta(seconds=1))["expired"])
                self.assertTrue(coord._escalation_expiry_info(rec, CREATED + ttl)["expired"])

    def test_unverifiable_expiry_fails_closed(self):
        self.assertTrue(coord._escalation_expiry_info({"kind": "escalation", "created_at": "?"}, INSIDE)["expired"])


class TestCrossProjectFeed(unittest.TestCase):
    def _ddb(self):
        fake = mock.MagicMock()
        fake.scan.return_value = {"Items": [{"project_id": {"S": "enceladus"}}, {"project_id": {"S": "devops"}}]}
        base = _escalation_item()
        data = {
            "enceladus": [dict(base, status="requested"),
                          dict(base, item_id="ENC-ESC-002", record_id="escalation#ENC-ESC-002",
                               status="denied", created_at="2026-07-01T00:00:00Z")],
            "devops": [dict(base, project_id="devops", item_id="DVP-ESC-001",
                            record_id="escalation#DVP-ESC-001", kind="tool_call",
                            created_at="2026-07-02T05:00:00Z"),
                       dict(base, project_id="devops", item_id="DVP-ESC-002",
                            record_id="escalation#DVP-ESC-002",
                            created_at="2026-06-01T00:00:00Z")],  # long expired, unswept
        }

        def _query(**kwargs):
            pid = kwargs["ExpressionAttributeValues"][":pid"]["S"]
            return {"Items": [_serialized(i) for i in data[pid]]}

        fake.query.side_effect = _query
        fake.get_item.side_effect = lambda TableName=None, Key=None, **kw: (
            {"Item": _serialized(_target_item())}
            if (Key or {}).get("record_id", {}).get("S", "").startswith("task#") else {})
        return fake

    def _feed(self, params):
        with mock.patch.object(coord, "_get_ddb", return_value=self._ddb()), \
             mock.patch.object(coord, "_gate_now", return_value=INSIDE):
            return coord._handle_escalations_feed({"queryStringParameters": params}, COGNITO_CLAIMS)

    def test_star_lists_all_projects_and_kinds(self):
        resp = self._feed({"project_id": "*"})
        self.assertEqual(200, resp["statusCode"])
        body = json.loads(resp["body"])
        ids = {e["item_id"] for e in body["pending"] + body["terminal"]}
        self.assertEqual({"ENC-ESC-001", "ENC-ESC-002", "DVP-ESC-001", "DVP-ESC-002"}, ids)
        self.assertEqual("all_projects", body["scope"])
        self.assertEqual(2, body["projects_scanned"])
        self.assertEqual({"ENC-ESC-001", "DVP-ESC-001"}, {e["item_id"] for e in body["pending"]})
        # expired-but-unswept 'requested' is not actionable: terminal, no diff
        expired = [e for e in body["terminal"] if e["item_id"] == "DVP-ESC-002"][0]
        self.assertEqual("expired", expired["state"])
        self.assertNotIn("diff", expired)
        self.assertEqual("tool_call", [e for e in body["pending"] if e["item_id"] == "DVP-ESC-001"][0]["kind"])
        self.assertEqual({"escalation", "tool_call"}, {e["kind"] for e in body["pending"] + body["terminal"]})

    def test_all_projects_param_state_and_kind_filters(self):
        body = json.loads(self._feed({"project_id": "enceladus", "all_projects": "true", "state": "expired"})["body"])
        self.assertEqual(["DVP-ESC-002"], [e["item_id"] for e in body["terminal"]])
        body = json.loads(self._feed({"project_id": "_", "kind": "tool_call"})["body"])
        self.assertEqual(["DVP-ESC-001"], [e["item_id"] for e in body["pending"] + body["terminal"]])

    def test_invalid_filters_400(self):
        self.assertEqual(400, self._feed({"kind": "nope"})["statusCode"])
        self.assertEqual(400, self._feed({"state": "nope"})["statusCode"])

    def test_default_single_project_shape_unchanged(self):
        fake = self._ddb()
        with mock.patch.object(coord, "_get_ddb", return_value=fake), \
             mock.patch.object(coord, "_gate_now", return_value=INSIDE):
            resp = coord._handle_escalations_feed({"queryStringParameters": None}, COGNITO_CLAIMS)
        body = json.loads(resp["body"])
        self.assertEqual({"success", "project_id", "pending", "terminal", "count"}, set(body))
        self.assertEqual("enceladus", body["project_id"])
        fake.scan.assert_not_called()

    def test_non_cognito_still_403(self):
        self.assertEqual(403, coord._handle_escalations_feed({"queryStringParameters": {"project_id": "*"}},
                                                             INTERNAL_CLAIMS)["statusCode"])


if __name__ == "__main__":
    unittest.main()
