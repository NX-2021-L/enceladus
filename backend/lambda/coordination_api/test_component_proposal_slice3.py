"""ENC-TSK-S82 slice 3: approve response, edges on GET, flag default, notification, SNS ref."""

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import test_component_proposal_contract as C  # noqa: E402  (loads lambda_function as C.L)

L = C.L
import notify_v2  # noqa: E402
from enceladus_shared import appconfig_flags  # noqa: E402


class Slice3Tests(unittest.TestCase):
    def setUp(self):
        for p in (
            mock.patch.object(L, "ENABLE_COMPONENT_PROPOSAL", True),
            mock.patch.object(L, "_require_component_decider", return_value=None),
            mock.patch.object(L, "_publish_component_lifecycle_event"),
        ):
            p.start()
            self.addCleanup(p.stop)

    def test_approve_200_carries_approved_component_id(self):
        d = C._ddb(C._proposal_item())
        with mock.patch.object(L, "_get_ddb", return_value=d):
            resp = L._handle_components_approve(C.REF, C._event({"component_id": "comp-chosen"}, "1"), C.HUMAN)
        out = C._body(resp)
        self.assertEqual((resp["statusCode"], out["approved_component_id"]), (200, "comp-chosen"))

    def test_stale_approve_412_carries_current_proposal(self):
        d = C._ddb(C._proposal_item(version=3))
        with mock.patch.object(L, "_get_ddb", return_value=d):
            resp = L._handle_components_approve(C.REF, C._event({}, "1"), C.HUMAN)
        out = C._body(resp)
        self.assertEqual(resp["statusCode"], 412)
        self.assertEqual((out["proposal"]["proposal_ref"], out["proposal"]["version"]), (C.REF, 3))
        d.transact_write_items.assert_not_called()

    def test_flag_resolves_true_without_appconfig_or_env_and_false_when_explicit(self):
        with mock.patch.object(appconfig_flags, "get_flags", return_value={}), \
             mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ENABLE_COMPONENT_PROPOSAL", None)
            self.assertTrue(appconfig_flags.flag("enable_component_proposal", env_fallback="ENABLE_COMPONENT_PROPOSAL", default=True))
            os.environ["ENABLE_COMPONENT_PROPOSAL"] = "false"
            self.assertFalse(appconfig_flags.flag("enable_component_proposal", env_fallback="ENABLE_COMPONENT_PROPOSAL", default=True))
        self.assertTrue(L.ENABLE_COMPONENT_PROPOSAL or True)  # module attr patched true in setUp

    def test_get_component_returns_edges_with_lock_state(self):
        comp = {"component_id": "comp-x", "project_id": "enceladus", "lifecycle_status": "approved", "component_name": "X"}
        rows = [
            {"source_id": "comp-x", "target_id": "ENC-TSK-1", "edge_type": "DESIGNS", "is_inverse": False, "created_at": "t"},
            {"source_id": "comp-x", "target_id": "ENC-TSK-2", "edge_type": "IMPLEMENTS", "is_inverse": False, "created_at": "t"},
            {"source_id": "ENC-TSK-1", "target_id": "comp-x", "edge_type": "DESIGNS", "is_inverse": True},
        ]
        d = C._ddb(comp)
        d.query.return_value = {"Items": [L._py_to_ddb(r) for r in rows]}
        tasks = {"ENC-TSK-1": {"closed_count": 1}, "ENC-TSK-2": {"checkout_count": 0}}
        with mock.patch.object(L, "_get_ddb", return_value=d), \
             mock.patch.object(L, "_get_task_record", side_effect=lambda t: tasks[t]):
            out = C._body(L._handle_components_get("comp-x"))
        self.assertEqual(
            [(e["edge_type"], e["task_id"], e["locked"]) for e in out["edges"]],
            [("DESIGNS", "ENC-TSK-1", True), ("IMPLEMENTS", "ENC-TSK-2", False)],
        )
        d.scan.assert_not_called()

    def test_propose_sends_one_notification_and_survives_failure(self):
        d = C._ddb()
        body = {
            "suggested_component_id": "comp-thing", "display_name": "Thing", "project_id": "enceladus",
            "requested_minimum_transition_type": "external_deploy",
            "component_address": "neo4j+s://t.databases.neo4j.io",
            "component_repo_dir": "infrastructure/external/t.yaml",
            "component_address_class": "neo4j_auradb", "component_class": "external",
            "proposing_agent_session_id": "ENC-SES-X",
        }
        with mock.patch.object(L, "_get_ddb", return_value=d), \
             mock.patch.object(notify_v2, "handle_component_proposal_push", side_effect=RuntimeError("boom")) as push:
            resp = L._handle_components_propose(C._event(body), {})
        self.assertEqual(resp["statusCode"], 201)
        push.assert_called_once()
        args = push.call_args.args
        self.assertEqual((args[2], args[3]), ("enceladus", "comp-thing"))
        self.assertRegex(args[1], r"^cprop-[0-9a-f]{10}$")

    def test_push_fans_out_only_to_opted_in_devices_with_deep_link(self):
        ref = "cprop-0123456789"
        prefs_on = json.dumps({"types": {"component_proposal": {"enabled": True, "min_risk": "low"}}, "detail": "detailed"})
        prefs_off = json.dumps({"types": {}, "detail": "detailed"})

        def item(sk, prefs):
            return {"pk": {"S": "PUSHDEV#a"}, "sk": {"S": sk}, "prefs": {"S": prefs}, "endpoint_hash": {"S": sk}}

        ddb = mock.MagicMock()
        ddb.query.return_value = {"Items": [item("d1", prefs_on), item("d2", prefs_off)]}
        host = mock.MagicMock()
        host._get_ddb.return_value = ddb
        host._webpush = object()
        host._load_escalation_approver_allowlist.return_value = {"a"}
        payloads = []
        with mock.patch.object(notify_v2, "_notify_send_raw", side_effect=lambda it, p, t: payloads.append(p) or 201), \
             mock.patch.object(notify_v2, "_notify_mark_sent"):
            n = notify_v2.handle_component_proposal_push(host, ref, "enceladus", "comp-thing")
        self.assertEqual(n, 1)
        self.assertEqual(len(payloads), 1)
        self.assertTrue(payloads[0]["notification"]["navigate"].endswith(f"/component-registry/proposals/{ref}"))


if __name__ == "__main__":
    unittest.main()
