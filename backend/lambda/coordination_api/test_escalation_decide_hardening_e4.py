"""ENC-TSK-967 (DVP-PLN-013 E4-W1.2, phase 2a): hardened escalation decide.

If-Match (escalation etag + subject version), callHash, Idempotency-Key,
no-self-review, inputs_schema, the hash-chained decision log (auth_method,
auth_time, assurance, degraded step_up) and the fail-closed applier registry.
The FTR-121 human-only preconditions are exercised in test_escalation_decision_j70.py.
"""
import datetime as dt
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

from test_escalation_decision_j70 import (  # noqa: E402
    COGNITO_CLAIMS, INTERNAL_CLAIMS, _escalation_item, _fake_ddb, _target_item,
    coordination_lambda as coord,
)

UTC = dt.timezone.utc
AUTH_TIME = int(dt.datetime(2026, 7, 2, 4, 58, tzinfo=UTC).timestamp())   # 2 min before the pinned clock
CLAIMS = dict(COGNITO_CLAIMS, auth_time=AUTH_TIME)
ZERO = "0" * 64


def _basis(item):
    return {"mutation_type": item["mutation_type"], "target_record_id": item["target_record_id"],
            "payload": json.loads(item["payload"])}


def _strict_item(**extra):
    item = _escalation_item()
    item["kind"] = "tool_call"
    item.update(extra)
    return item


def _fresh_proof(claims=None):
    return {"method": "cognito_max_age", "auth_time": (claims or CLAIMS).get("auth_time")}


def _decide(item, decision="approve", body=None, headers=None, claims=None, target=None, subject=None,
            proof=True, now=None):
    body = dict(body or {})
    if proof and not any(k in body for k in ("stepUp", "step_up", "proof")):
        body["stepUp"] = _fresh_proof(claims)   # high-risk cards need a fresh proof (DVP-TSK-980)
    ddb = _fake_ddb(escalation=item, target=target or _target_item())
    invoke = mock.MagicMock(return_value={"success": True, "status": "applied", "_status_code": 200,
                                          "result": {"ok": True}})
    event = {"body": json.dumps(body), "headers": headers or {}, "queryStringParameters": None}
    with mock.patch.object(coord, "_get_ddb", return_value=ddb), \
         mock.patch.object(coord, "_gate_now", new=(lambda: now) if now else coord._gate_now), \
         mock.patch.object(coord, "_invoke_tracker_mutation_api", invoke), \
         mock.patch.object(coord, "_load_escalation_approver_allowlist", return_value={"io@jreese.net"}):
        resp = coord._handle_escalation_decision(
            "enceladus", "ENC-ESC-001", decision, event, claims or CLAIMS)
    return resp, ddb, invoke


def _entries(ddb):
    out = []
    for call in ddb.update_item.call_args_list:
        values = call.kwargs["ExpressionAttributeValues"]
        typed = values.get(":log_entry") or values.get(":entry")
        if typed:
            out.extend(coord._deserialize({"x": typed})["x"])
    return out


def _strict_headers(item, key="k-1"):
    return {"If-Match": coord._escalation_etag(item), "Idempotency-Key": key}


def _strict_body(item, **extra):
    body = {"callHash": coord._gate_call_hash(_basis(item)), "subject_version": "4"}
    body.update(extra)
    return body


class TestIfMatchAndCallHash(unittest.TestCase):
    def test_strict_happy_path_with_every_precondition(self):
        item = _strict_item()
        resp, ddb, invoke = _decide(item, body=_strict_body(item), headers=_strict_headers(item))
        self.assertEqual(200, resp["statusCode"], resp["body"])
        invoke.assert_called_once()
        self.assertEqual(2, len(ddb.update_item.call_args_list))    # decided + executed

    def test_missing_if_match_is_428_for_non_legacy_kind(self):
        item = _strict_item()
        resp, ddb, invoke = _decide(item, body=_strict_body(item), headers={"Idempotency-Key": "k"})
        self.assertEqual(428, resp["statusCode"])
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()

    def test_legacy_record_without_preconditions_still_decides(self):
        resp, _ddb, invoke = _decide(_escalation_item())      # D9: legacy clients unchanged
        self.assertEqual(200, resp["statusCode"])
        invoke.assert_called_once()

    def test_stale_card_etag_is_412_card_changed(self):
        item = _strict_item()
        headers = _strict_headers(item)
        headers["If-Match"] = '"deadbeef"'
        resp, ddb, invoke = _decide(item, body=_strict_body(item), headers=headers)
        body = json.loads(resp["body"])
        self.assertEqual(412, resp["statusCode"])
        self.assertEqual("card_changed", body["reason"])
        self.assertEqual(coord._escalation_etag(item), body["etag"])   # current etag for the re-render
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()

    def test_subject_version_mismatch_is_412_subject_changed_and_fires_nothing(self):
        item = _strict_item()
        resp, ddb, invoke = _decide(item, body=_strict_body(item, subject_version="3"),
                                    headers=_strict_headers(item))
        body = json.loads(resp["body"])
        self.assertEqual(412, resp["statusCode"])
        self.assertEqual("subject_changed", body["reason"])
        self.assertEqual("4", body["subject_version"])
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()

    def test_deny_skips_the_subject_check(self):
        item = _strict_item()
        resp, ddb, invoke = _decide(item, "deny", body={"subject_version": "1", "guidance_note": "no"},
                                    headers=_strict_headers(item))
        self.assertEqual(200, resp["statusCode"], resp["body"])
        invoke.assert_not_called()
        self.assertEqual("deny", _entries(ddb)[0]["verdict"])

    def test_wrong_call_hash_is_409_and_fires_nothing(self):
        item = _strict_item()
        resp, ddb, invoke = _decide(item, body=_strict_body(item, callHash="0" * 64),
                                    headers=_strict_headers(item))
        self.assertEqual(409, resp["statusCode"])
        self.assertEqual("call_changed", json.loads(resp["body"])["reason"])
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()

    def test_stored_call_hash_that_no_longer_matches_the_record_is_409(self):
        item = _strict_item(callHash="a" * 64)    # record was edited after the hash was stored
        resp, ddb, invoke = _decide(item, body=_strict_body(item), headers=_strict_headers(item))
        self.assertEqual(409, resp["statusCode"])
        invoke.assert_not_called()

    def test_candidate_must_come_from_candidates(self):
        cands = [{"id": "c1", "call": {"a": 1}}, {"id": "c2", "call": {"a": 2}}]
        item = _strict_item(candidates=cands)
        body = {"callHash": coord._gate_call_hash({"a": 2}), "subject_version": "4", "candidateId": "c2"}
        ok, _ddb, _inv = _decide(item, body=body, headers=_strict_headers(item))
        self.assertEqual(200, ok["statusCode"], ok["body"])
        for bad in ({}, {"candidateId": "zzz"}):
            resp, ddb, invoke = _decide(item, body=dict(body, **{"candidateId": bad.get("candidateId", "")}),
                                        headers=_strict_headers(item))
            self.assertEqual(422, resp["statusCode"])
            invoke.assert_not_called()


class TestIdempotencyAndSelfReview(unittest.TestCase):
    def test_repeat_with_same_key_returns_first_result_without_a_second_write(self):
        item = _strict_item()
        body, headers = _strict_body(item), _strict_headers(item, "key-77")
        first, ddb1, invoke1 = _decide(item, body=body, headers=headers)
        self.assertEqual(200, first["statusCode"])
        log = _entries(ddb1)
        decided = _item_after(item, log, "approved")
        second, ddb2, invoke2 = _decide(decided, body=body, headers=headers)
        out = json.loads(second["body"])
        self.assertEqual(200, second["statusCode"], second["body"])
        self.assertTrue(out["idempotent_replay"])
        self.assertEqual(log[0]["hash"], out["decision_entry"]["hash"])
        ddb2.update_item.assert_not_called()
        invoke2.assert_not_called()

    def test_same_key_with_a_different_payload_is_422(self):
        item = _strict_item()
        body, headers = _strict_body(item), _strict_headers(item, "key-77")
        _first, ddb1, _inv = _decide(item, body=body, headers=headers)
        decided = _item_after(item, _entries(ddb1), "approved")
        resp, ddb2, _inv2 = _decide(decided, "deny", body={"guidance_note": "x"}, headers=headers)
        self.assertEqual(422, resp["statusCode"])
        ddb2.update_item.assert_not_called()

    def test_decided_escalation_with_a_new_key_is_409(self):
        item = _strict_item()
        resp, _ddb, _inv = _decide(_item_after(item, [], "approved"), body=_strict_body(item),
                                   headers=_strict_headers(item, "new-key"))
        self.assertEqual(409, resp["statusCode"])

    def test_requester_cannot_decide_their_own_escalation(self):
        item = _escalation_item()
        item["requested_by"] = {"session_id": "ENC-SES-02F", "email": "IO@jreese.net"}
        resp, ddb, invoke = _decide(item)
        self.assertEqual(403, resp["statusCode"])
        self.assertEqual("self_review", json.loads(resp["body"])["reason"])
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()

    def test_distinct_from_principals_cannot_decide(self):
        item = _escalation_item()
        item["distinct_from"] = ["someone", "abc-123"]       # the decider's Cognito sub
        resp, ddb, _inv = _decide(item)
        self.assertEqual(403, resp["statusCode"])
        ddb.update_item.assert_not_called()

    def test_source_principal_cannot_decide(self):
        item = _escalation_item()
        item["source_principal"] = "io@jreese.net"
        self.assertEqual(403, _decide(item)[0]["statusCode"])

    def test_machine_credentials_still_cannot_reach_decide(self):
        item = _strict_item()
        resp, ddb, _inv = _decide(item, headers=_strict_headers(item), claims=INTERNAL_CLAIMS)
        self.assertEqual(403, resp["statusCode"])
        ddb.update_item.assert_not_called()


def _item_after(item, log, status):
    out = dict(item)
    out["status"] = status
    out["decision_log"] = log
    return out


class TestInputsSchema(unittest.TestCase):
    SCHEMA = {"type": "object", "required": ["window"], "additionalProperties": False,
              "properties": {"window": {"type": "integer", "minimum": 1, "maximum": 30},
                             "note": {"type": "string", "maxLength": 10}}}

    def test_invalid_inputs_are_422(self):
        for inputs in ({}, {"window": 99}, {"window": 3, "extra": 1}, {"window": "3"}):
            item = _escalation_item()
            item["inputs_schema"] = json.dumps(self.SCHEMA)
            resp, ddb, invoke = _decide(item, body={"inputs": inputs})
            self.assertEqual(422, resp["statusCode"], inputs)
            self.assertEqual("inputs_invalid", json.loads(resp["body"])["reason"])
            ddb.update_item.assert_not_called()
            invoke.assert_not_called()

    def test_valid_inputs_are_stored_as_decision_inputs(self):
        item = _escalation_item()
        item["inputs_schema"] = self.SCHEMA
        resp, ddb, _inv = _decide(item, body={"inputs": {"window": 7}})
        self.assertEqual(200, resp["statusCode"], resp["body"])
        values = ddb.update_item.call_args_list[0].kwargs["ExpressionAttributeValues"]
        record = coord._deserialize({"x": values[":decision_record"]})["x"]
        self.assertEqual({"window": 7}, record["inputs"])


class TestHashChainedLog(unittest.TestCase):
    def test_every_entry_records_auth_method_auth_time_and_assurance(self):
        item = _escalation_item()
        resp, ddb, _inv = _decide(item)
        self.assertEqual(200, resp["statusCode"])
        log = _entries(ddb)
        self.assertEqual(["decided", "executed"], [e["event"] for e in log])
        for entry in log:
            self.assertEqual("interactive_human", entry["auth_method"])
            self.assertEqual("2026-07-02T04:58:00Z", entry["auth_time"])
            self.assertEqual("aal2", entry["assurance"])   # default kind risk is high: proof required
        self.assertEqual({"status": 200, "resultRef": "ENC-ESC-001"}, log[1]["result"])

    def test_chain_links_and_verifies_across_a_prior_entry(self):
        item = _escalation_item()
        prior = coord._escalation_log_entry(1, ZERO, {"event": "snoozed", "cardId": "ENC-ESC-001",
                                                      "auth_method": "interactive_human",
                                                      "auth_time": None, "assurance": "aal1"})
        item["decision_log"] = [prior]
        _resp, ddb, _inv = _decide(item)
        log = _entries(ddb)
        self.assertEqual(2, log[0]["seq"])
        self.assertEqual(prior["hash"], log[0]["prevHash"])
        self.assertEqual(log[0]["hash"], log[1]["prevHash"])
        chain = [prior] + log
        self.assertEqual((True, None), coord._verify_decision_chain(chain))
        tampered = [dict(chain[0], event="expired")] + chain[1:]
        self.assertEqual((False, 1), coord._verify_decision_chain(tampered))
        # the first entry of a fresh chain anchors on 64 zeros
        _r, fresh_ddb, _i = _decide(_escalation_item())
        self.assertEqual(ZERO, _entries(fresh_ddb)[0]["prevHash"])

    def test_tampered_chain_refuses_to_extend(self):
        item = _escalation_item()
        prior = coord._escalation_log_entry(1, ZERO, {"event": "snoozed", "cardId": "ENC-ESC-001",
                                                      "auth_method": "interactive_human",
                                                      "auth_time": None, "assurance": "aal1"})
        item["decision_log"] = [dict(prior, event="forged")]
        resp, ddb, invoke = _decide(item)
        self.assertEqual(409, resp["statusCode"])
        self.assertEqual("log_integrity", json.loads(resp["body"])["reason"])
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()

    def test_decided_entry_is_written_with_the_status_transition_before_execution(self):
        order = []
        item = _escalation_item()
        ddb = _fake_ddb(escalation=item, target=_target_item())
        ddb.update_item.side_effect = lambda **kw: order.append("write")
        invoke = mock.MagicMock(side_effect=lambda *a, **k: order.append("apply") or
                                {"success": True, "status": "applied", "_status_code": 200})
        with mock.patch.object(coord, "_get_ddb", return_value=ddb), \
             mock.patch.object(coord, "_invoke_tracker_mutation_api", invoke), \
             mock.patch.object(coord, "_load_escalation_approver_allowlist", return_value={"io@jreese.net"}):
            coord._handle_escalation_decision("enceladus", "ENC-ESC-001", "approve",
                                              {"body": json.dumps({"stepUp": _fresh_proof()}), "headers": {}}, CLAIMS)
        self.assertEqual(["write", "apply", "write"], order)

    def test_unverified_step_up_method_is_retired_everywhere(self):
        for item in (_escalation_item(), _low_item()):
            resp, ddb, invoke = _decide(item, body={"stepUp": {"method": "step_up"}})
            self.assertEqual(403, resp["statusCode"])
            self.assertEqual("step_up_unverified", json.loads(resp["body"])["reason"])
            ddb.update_item.assert_not_called()
            invoke.assert_not_called()

    def test_valid_cognito_max_age_proof_raises_assurance(self):
        proof = {"method": "cognito_max_age", "auth_time": AUTH_TIME}
        resp, ddb, _inv = _decide(_escalation_item(), body={"stepUp": proof})
        self.assertEqual(200, resp["statusCode"], resp["body"])
        for entry in _entries(ddb):
            self.assertEqual("aal2", entry["assurance"])
            self.assertEqual("cognito_max_age", entry["proof_method"])

    def test_stale_or_foreign_proofs_are_refused_not_downgraded(self):
        stale = dict(CLAIMS, auth_time=AUTH_TIME - 3600)
        cases = [
            ({"method": "cognito_max_age", "auth_time": AUTH_TIME - 3600}, stale),
            ({"method": "cognito_max_age", "auth_time": AUTH_TIME - 5}, CLAIMS),   # not the token's auth_time
            ({"method": "webauthn", "auth_time": AUTH_TIME}, CLAIMS),               # unverifiable method
        ]
        for proof, claims in cases:
            resp, ddb, invoke = _decide(_escalation_item(), body={"stepUp": proof}, claims=claims)
            self.assertEqual(403, resp["statusCode"], proof)
            self.assertIn(json.loads(resp["body"])["reason"],
                          ("step_up_required", "method_not_enabled"), proof)
            ddb.update_item.assert_not_called()
            invoke.assert_not_called()

    def test_get_view_exposes_etag_and_the_verified_chain(self):
        item = _escalation_item()
        entry = coord._escalation_log_entry(1, ZERO, {"event": "decided", "cardId": "ENC-ESC-001",
                                                      "auth_method": "interactive_human",
                                                      "auth_time": None, "assurance": "aal1"})
        item["decision_log"] = [entry]
        coord._escalation_gate_view(item)
        self.assertEqual([entry], item["decision_log"])
        self.assertEqual(entry["hash"], item["decision_log_head"])
        self.assertTrue(item["decision_log_valid"])
        self.assertTrue(item["etag"].startswith('"'))
        legacy = _escalation_item()
        coord._escalation_gate_view(legacy)
        self.assertEqual([], legacy["decision_log"])


class TestApplierRegistry(unittest.TestCase):
    def test_unknown_subject_type_is_refused_before_any_write(self):
        item = _escalation_item(mutation_type="unregistered_type")
        resp, ddb, invoke = _decide(item)
        self.assertEqual(422, resp["statusCode"])
        self.assertEqual("unsupported_subject_type", json.loads(resp["body"])["reason"])
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()

    def test_deny_of_an_unknown_subject_type_still_works(self):
        item = _escalation_item(mutation_type="unregistered_type")
        resp, _ddb, invoke = _decide(item, "deny")
        self.assertEqual(200, resp["statusCode"])
        invoke.assert_not_called()

    def test_legacy_types_are_registered_by_default(self):
        self.assertIn("deploy_arc_change", coord._ESCALATION_APPLIERS)
        self.assertIn("direct_state_override", coord._ESCALATION_APPLIERS)

    def test_a_registered_applier_is_used_and_double_registration_is_refused(self):
        applier = mock.MagicMock(return_value={"status": "applied", "_status_code": 200, "result": {"r": 1}})
        coord.register_escalation_applier("recipe_test", applier)
        try:
            with self.assertRaises(ValueError):
                coord.register_escalation_applier("recipe_test", applier)
            item = _escalation_item(mutation_type="recipe_test")
            resp, _ddb, invoke = _decide(item)
            self.assertEqual(200, resp["statusCode"], resp["body"])
            applier.assert_called_once()
            invoke.assert_not_called()
        finally:
            coord._ESCALATION_APPLIERS.pop("recipe_test", None)


if __name__ == "__main__":
    unittest.main()


def _low_item():
    item = _escalation_item()
    item["risk"] = "low"            # no step-up required
    return item


class TestStepUpEnforcement(unittest.TestCase):
    """DVP-TSK-980: high|critical (or requiredAuth step_up) verdicts need a fresh proof."""

    def _reason(self, resp):
        return json.loads(resp["body"]).get("reason")

    def test_card_refused_without_proof_for_approve_and_deny(self):
        for decision in ("approve", "deny"):
            for item in (_escalation_item(), dict(_low_item(), requiredAuth="step_up"),
                         dict(_low_item(), risk="critical")):
                resp, ddb, invoke = _decide(item, decision=decision, proof=False)
                self.assertEqual(403, resp["statusCode"], (decision, item.get("kind")))
                self.assertEqual("step_up_required", self._reason(resp))
                ddb.update_item.assert_not_called()
                invoke.assert_not_called()

    def test_stale_proof_refused(self):
        stale = dict(CLAIMS, auth_time=AUTH_TIME - 3600)
        resp, ddb, _inv = _decide(_escalation_item(), claims=stale, proof=False,
                                  body={"stepUp": {"method": "cognito_max_age", "auth_time": AUTH_TIME - 3600}})
        self.assertEqual(403, resp["statusCode"])
        self.assertEqual("step_up_required", self._reason(resp))
        ddb.update_item.assert_not_called()

    def test_webauthn_is_a_reserved_slot(self):
        resp, ddb, _inv = _decide(_escalation_item(), proof=False,
                                  body={"stepUp": {"method": "webauthn", "auth_time": AUTH_TIME}})
        self.assertEqual(403, resp["statusCode"])
        self.assertEqual("method_not_enabled", self._reason(resp))
        self.assertNotIn("webauthn", coord._STEP_UP_VERIFIERS)
        ddb.update_item.assert_not_called()

    def test_fresh_proof_accepted_for_cognito_and_hub_principal(self):
        hub = coord._hub_exchange.principal_claims({
            "sub": "hub-sub-1", "email": "io@jreese.net", "auth_time": AUTH_TIME, "src_name": "enceladus",
            "src_iss": "https://idp.example", "iat": AUTH_TIME + 30, "exp": AUTH_TIME + 3600})
        for claims in (CLAIMS, hub):
            resp, ddb, _inv = _decide(_escalation_item(), claims=claims, proof=False,
                                      body={"stepUp": _fresh_proof(claims)})
            self.assertEqual(200, resp["statusCode"], resp["body"])
            entries = _entries(ddb)
            self.assertTrue(entries)
            for entry in entries:
                self.assertEqual("aal2", entry["assurance"])
                self.assertEqual("cognito_max_age", entry["proof_method"])
                self.assertEqual(claims.get("auth_method") or "interactive_human", entry["auth_method"])
                self.assertTrue(entry["auth_time"])
                self.assertNotIn("degraded_mode", entry)

    def test_lower_assurance_card_unaffected_and_logs_the_three_fields(self):
        resp, ddb, _inv = _decide(_low_item(), proof=False)
        self.assertEqual(200, resp["statusCode"], resp["body"])
        for entry in _entries(ddb):
            self.assertEqual("interactive_human", entry["auth_method"])
            self.assertEqual("aal1", entry["assurance"])
            self.assertTrue(entry["auth_time"])
            self.assertNotIn("degraded_mode", entry)

    def test_undeterminable_auth_context_refused_before_any_write(self):
        bare = {k: v for k, v in CLAIMS.items() if k not in ("auth_time", "iat")}
        resp, ddb, invoke = _decide(_low_item(), claims=bare, proof=False)
        self.assertEqual(403, resp["statusCode"])
        self.assertEqual("auth_context_incomplete", self._reason(resp))
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()
