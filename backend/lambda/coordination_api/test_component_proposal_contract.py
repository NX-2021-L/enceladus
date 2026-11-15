"""Tests for the component proposal contract (ENC-TSK-S82 slice 2).

A proposal is a cprop-<10 hex> record in component-registry. The human decider
mints the component ID at approval in one TransactWriteItems; reject writes no
component. Reuses the module-load pattern of test_component_decider_guard.py.
"""

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
L = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = L
_SPEC.loader.exec_module(L)

REF = "cprop-0123456789"
HUMAN = {"auth_mode": "cognito", "token_use": "id", "aud": "c", "email": "io@example.com", "sub": "s"}


class _TCE(Exception):
    pass


class _CCF(Exception):
    pass


def _s(v):
    return {"S": v}


def _proposal_item(**over):
    item = {
        "component_id": REF, "record_kind": "proposal", "proposal_status": "pending",
        "version": 1, "lifecycle_status": "proposed", "component_name": "Thing",
        "project_id": "enceladus", "suggested_component_id": "comp-thing",
        "requested_minimum_transition_type": "code", "proposing_agent_session_id": "ENC-SES-X",
        "proposed_at": "2026-11-15T00:00:00Z", "description": "d", "source_paths": ["a/"],
        "component_address": "addr", "component_repo_dir": "dir",
        "component_address_class": "cls", "component_class": "internal",
    }
    item.update(over)
    return item


def _ddb(item=None, **over):
    d = mock.MagicMock()
    d.scan.return_value = {"Items": []}
    d.exceptions.TransactionCanceledException = _TCE
    d.exceptions.ConditionalCheckFailedException = _CCF
    d.get_item.return_value = {"Item": L._py_to_ddb(item)} if item else {}
    for k, v in over.items():
        setattr(d, k, v)
    return d


def _event(body=None, if_match=None, **extra):
    headers = {"If-Match": if_match} if if_match is not None else {}
    return {"body": json.dumps(body or {}), "headers": headers, **extra}


def _body(resp):
    return json.loads(resp["body"])


class ProposalContractTests(unittest.TestCase):
    def setUp(self):
        for patcher in (
            mock.patch.object(L, "ENABLE_COMPONENT_PROPOSAL", True),
            mock.patch.object(L, "_require_component_decider", return_value=None),
            mock.patch.object(L, "_publish_component_lifecycle_event"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _approve(self, ddb, body=None, if_match="1"):
        with mock.patch.object(L, "_get_ddb", return_value=ddb):
            return L._handle_components_approve(REF, _event(body, if_match), HUMAN)

    def _reject(self, ddb, body=None, if_match="1"):
        body = body if body is not None else {"rejection_reason": "duplicate of an existing component"}
        with mock.patch.object(L, "_get_ddb", return_value=ddb):
            return L._handle_components_reject(REF, _event(body, if_match), HUMAN)

    def test_propose_returns_ref_and_no_component_id(self):
        d = _ddb()
        body = {
            "suggested_component_id": "comp-thing", "display_name": "Thing", "project_id": "enceladus",
            "requested_minimum_transition_type": "external_deploy",
            "component_address": "neo4j+s://t.databases.neo4j.io",
            "component_repo_dir": "infrastructure/external/t.yaml",
            "component_address_class": "neo4j_auradb", "component_class": "external",
            "proposing_agent_session_id": "ENC-SES-X",
        }
        with mock.patch.object(L, "_get_ddb", return_value=d):
            resp = L._handle_components_propose(_event(body), {})
        out = _body(resp)
        self.assertEqual(resp["statusCode"], 201)
        self.assertNotIn("component_id", out)
        self.assertRegex(out["proposal_ref"], r"^cprop-[0-9a-f]{10}$")
        self.assertEqual((out["proposal_status"], out["version"], out["suggested_component_id"]), ("pending", 1, "comp-thing"))
        put = d.transact_write_items.call_args.kwargs["TransactItems"][0]["Put"]["Item"]
        self.assertEqual(put["proposal_status"]["S"], "pending")
        self.assertEqual(put["component_id"]["S"], out["proposal_ref"])

    def test_approve_mints_chosen_id_in_one_transaction(self):
        d = _ddb(_proposal_item())
        resp = self._approve(d, {"component_id": "comp-chosen", "required_transition_type": "external_deploy"})
        self.assertEqual(resp["statusCode"], 200)
        d.transact_write_items.assert_called_once()
        put, upd = d.transact_write_items.call_args.kwargs["TransactItems"]
        item = put["Put"]["Item"]
        self.assertEqual(item["component_id"]["S"], "comp-chosen")
        self.assertEqual(item["lifecycle_status"]["S"], "approved")
        self.assertEqual(item["required_transition_type"]["S"], "external_deploy")
        self.assertEqual(item["proposal_ref"]["S"], REF)
        self.assertEqual(item["approved_by"]["S"], "io@example.com")
        self.assertNotIn("record_kind", item)
        self.assertEqual(put["Put"]["ConditionExpression"], "attribute_not_exists(component_id)")
        vals = upd["Update"]["ExpressionAttributeValues"]
        self.assertEqual(vals[":cid"]["S"], "comp-chosen")
        self.assertEqual(vals[":expected"]["N"], "1")
        self.assertIn("proposal_status = :pending", upd["Update"]["ConditionExpression"])
        self.assertEqual(_body(resp)["component_id"], "comp-chosen")

    def test_propose_meta_sentinels_validate_against_suggestion(self):
        d = _ddb()
        body = {
            "suggested_component_id": "comp-umb", "display_name": "Umb", "project_id": "enceladus",
            "requested_minimum_transition_type": "documentation",
            "component_address": "meta:comp-umb", "component_repo_dir": "meta:comp-umb",
            "component_address_class": "meta", "component_class": "meta",
            "proposing_agent_session_id": "ENC-SES-X",
        }
        with mock.patch.object(L, "_get_ddb", return_value=d):
            resp = L._handle_components_propose(_event(body), {})
            self.assertEqual(resp["statusCode"], 201, resp["body"])
            put = d.transact_write_items.call_args.kwargs["TransactItems"][0]["Put"]["Item"]
            self.assertEqual(put["component_address"]["S"], "meta:comp-umb")
            bad = dict(body, component_address="meta:comp-other")
            self.assertEqual(L._handle_components_propose(_event(bad), {})["statusCode"], 422)

    def test_approve_meta_rewrites_sentinels_with_and_without_override(self):
        for body, want in (({}, "comp-thing"), ({"component_id": "comp-chosen"}, "comp-chosen")):
            d = _ddb(_proposal_item(
                component_address_class="meta", component_class="meta",
                component_address="meta:comp-thing", component_repo_dir="meta:comp-thing"))
            resp = self._approve(d, body)
            self.assertEqual(resp["statusCode"], 200, resp["body"])
            item = d.transact_write_items.call_args.kwargs["TransactItems"][0]["Put"]["Item"]
            self.assertEqual(item["component_address"]["S"], f"meta:{want}")
            self.assertEqual(item["component_repo_dir"]["S"], f"meta:{want}")

    def test_approve_defaults_to_suggestion_and_requested_type(self):
        d = _ddb(_proposal_item())
        resp = self._approve(d, {})
        self.assertEqual(resp["statusCode"], 200)
        item = d.transact_write_items.call_args.kwargs["TransactItems"][0]["Put"]["Item"]
        self.assertEqual(item["component_id"]["S"], "comp-thing")
        self.assertEqual(item["required_transition_type"]["S"], "code")

    def test_approve_without_any_id_or_bad_id_is_400(self):
        self.assertEqual(self._approve(_ddb(_proposal_item(suggested_component_id="")), {})["statusCode"], 400)
        self.assertEqual(self._approve(_ddb(_proposal_item()), {"component_id": "Comp_Bad"})["statusCode"], 400)

    def test_approve_taken_id_409(self):
        err = _TCE()
        err.response = {"CancellationReasons": [{"Code": "ConditionalCheckFailed"}, {"Code": "None"}]}
        d = _ddb(_proposal_item(), transact_write_items=mock.MagicMock(side_effect=err))
        resp = self._approve(d, {})
        self.assertEqual(resp["statusCode"], 409)

    def test_approve_stale_version_412_with_current_view(self):
        d = _ddb(_proposal_item(version=3))
        resp = self._approve(d, {}, if_match="1")
        self.assertEqual(resp["statusCode"], 412)
        self.assertEqual(_body(resp)["proposal"]["version"], 3)
        d.transact_write_items.assert_not_called()

    def test_approve_race_lost_412(self):
        err = _TCE()
        err.response = {"CancellationReasons": [{"Code": "None"}, {"Code": "ConditionalCheckFailed"}]}
        d = _ddb(_proposal_item(), transact_write_items=mock.MagicMock(side_effect=err))
        self.assertEqual(self._approve(d, {})["statusCode"], 412)

    def test_approve_non_pending_412(self):
        d = _ddb(_proposal_item(proposal_status="rejected"))
        self.assertEqual(self._approve(d, {})["statusCode"], 412)

    def test_approve_without_version_428_and_body_version_accepted(self):
        d = _ddb(_proposal_item())
        self.assertEqual(self._approve(d, {}, if_match=None)["statusCode"], 428)
        self.assertEqual(self._approve(d, {"expected_version": 1}, if_match=None)["statusCode"], 200)

    def test_approve_unknown_proposal_404(self):
        self.assertEqual(self._approve(_ddb(None), {})["statusCode"], 404)

    def test_reject_writes_no_component(self):
        d = _ddb(_proposal_item(), update_item=mock.MagicMock(return_value={"Attributes": L._py_to_ddb(
            _proposal_item(proposal_status="rejected", version=2, lifecycle_status="archived",
                           rejection_reason="duplicate of an existing component"))}))
        resp = self._reject(d)
        self.assertEqual(resp["statusCode"], 200)
        d.transact_write_items.assert_not_called()
        d.put_item.assert_not_called()
        kw = d.update_item.call_args.kwargs
        self.assertEqual(kw["ExpressionAttributeValues"][":archived"]["S"], "archived")
        self.assertEqual(kw["ExpressionAttributeValues"][":rejected"]["S"], "rejected")
        out = _body(resp)
        self.assertEqual(out["proposal"]["rejection_reason"], "duplicate of an existing component")
        self.assertEqual(out["version"], 2)

    def test_reject_reason_short_400_missing_version_428_stale_412(self):
        d = _ddb(_proposal_item())
        self.assertEqual(self._reject(d, {"rejection_reason": "short"})["statusCode"], 400)
        self.assertEqual(self._reject(d, if_match=None)["statusCode"], 428)
        self.assertEqual(self._reject(_ddb(_proposal_item(version=2)))["statusCode"], 412)

    def test_get_proposal_views_ignore_opacity(self):
        pending = _proposal_item()
        approved = _proposal_item(proposal_status="approved", lifecycle_status="archived", version=2,
                                  approved_component_id="comp-chosen")
        rejected = _proposal_item(proposal_status="rejected", lifecycle_status="archived", version=2,
                                  rejection_reason="no thanks, duplicate")
        views = []
        for item in (pending, approved, rejected):
            with mock.patch.object(L, "_get_ddb", return_value=_ddb(item)):
                resp = L._handle_components_get(REF)
            self.assertEqual(resp["statusCode"], 200)
            views.append(_body(resp)["proposal"])
        self.assertNotIn("approved_component_id", views[0])
        self.assertNotIn("rejection_reason", views[0])
        self.assertEqual(views[0]["suggested_component_id"], "comp-thing")
        self.assertEqual(views[1]["approved_component_id"], "comp-chosen")
        self.assertNotIn("rejection_reason", views[1])
        self.assertEqual(views[2]["rejection_reason"], "no thanks, duplicate")
        self.assertNotIn("approved_component_id", views[2])

    def test_list_excludes_proposals_unless_kind_proposal(self):
        comp = {"component_id": "comp-a", "project_id": "enceladus", "lifecycle_status": "approved"}
        items = [comp, _proposal_item(), _proposal_item(component_id="cprop-aaaaaaaaaa", proposal_status="approved")]
        d = _ddb(scan=mock.MagicMock(return_value={"Items": [L._py_to_ddb(i) for i in items]}))
        with mock.patch.object(L, "_get_ddb", return_value=d):
            plain = _body(L._handle_components_list({"queryStringParameters": {}}))
            pend = _body(L._handle_components_list({"queryStringParameters": {"kind": "proposal"}}))
            appr = _body(L._handle_components_list(
                {"queryStringParameters": {"kind": "proposal", "proposal_status": "approved"}}))
        self.assertEqual([c["component_id"] for c in plain["components"]], ["comp-a"])
        self.assertEqual([p["proposal_ref"] for p in pend["proposals"]], [REF])
        self.assertEqual([p["proposal_ref"] for p in appr["proposals"]], ["cprop-aaaaaaaaaa"])

    def test_decider_guard_still_applies_to_proposals(self):
        with mock.patch.object(L, "_require_component_decider", return_value=L._error(403, "no", code="COMPONENT_DECIDER_REQUIRED")):
            resp = L._handle_components_approve(REF, _event({}, "1"), {"auth_mode": "internal-key"})
        self.assertEqual(resp["statusCode"], 403)


if __name__ == "__main__":
    unittest.main()
