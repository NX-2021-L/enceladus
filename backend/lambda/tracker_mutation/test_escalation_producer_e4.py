"""ENC-TSK-967 (DVP-PLN-013 E4-W1.2, phase 2b): the producer API of escalation.request.

think and vagamod post gate cards under per-source principals
(GATE_PRODUCER_PRINCIPALS, fail-closed). Exactly one of proposedCalls or
candidates for decision kinds; telemetry kinds (drift, notice) carry neither;
legacy mutation_type requests are unchanged.
"""
import json
import os
import unittest
from unittest import mock

import test_escalation_gate_e4 as gate
from test_escalation_j68 import _request_body

NOW = gate.NOW
ALLOW = json.dumps({"think": ["think-prod"], "vagamod": ["vagamod-prod", "shared"], "other": ["shared"]})
CALL = {
    "capability": "tracker.set", "method": "POST", "path": "/enceladus/task/ENC-TSK-J10",
    "args": {"field": "title"}, "annotations": {"readOnlyHint": False, "destructiveHint": False},
    "ifMatch": "3", "callHash": "a" * 64,
}
CANDS = [{"id": "link", "label": "Link duplicate"}, {"id": "skip", "label": "Skip"}]


def _producer(**overrides):
    body = {"kind": "tool_call", "source_principal": "think-prod", "title": "Run the promote",
            "proposedCalls": [dict(CALL)]}
    body.update(overrides)
    return {k: v for k, v in body.items() if v is not None}


class _ProducerBase(gate._Base):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"GATE_PRODUCER_PRINCIPALS": ALLOW})
        env.start()
        self.addCleanup(env.stop)

    def _post(self, body):
        ddb = mock.MagicMock()
        ddb.get_item.return_value = {"Item": gate._TARGET_TASK_ITEM}
        with mock.patch.object(self.lf, "_get_ddb", return_value=ddb), \
             mock.patch.object(self.lf, "_get_project_prefix", return_value="ENC"), \
             mock.patch.object(self.lf, "_next_record_id", return_value="ENC-ESC-901"), \
             mock.patch.object(self.lf, "_notify_escalation_event"):
            resp = self.lf._handle_escalation_request("enceladus", body)
        return resp, ddb

    def _stored(self, ddb):
        return ddb.put_item.call_args.kwargs["Item"]


class TestProducerAccept(_ProducerBase):
    def test_think_proposed_calls_accepted_with_f10_expiry(self):
        resp, ddb = self._post(_producer())
        self.assertEqual(201, resp["statusCode"], resp["body"])
        body = json.loads(resp["body"])
        self.assertEqual(("tool_call", "decision", "think"), (body["kind"], body["family"], body["source"]))
        self.assertEqual(gate._z(NOW + gate.F10["tool_call"][0]), body["expiresAt"])
        item = self._stored(ddb)
        self.assertNotIn("mutation_type", item)
        self.assertEqual("think-prod", item["sourcePrincipal"]["S"])
        self.assertEqual("think-prod", item["requested_by"]["M"]["session_id"]["S"])
        self.assertEqual("requested", item["status"]["S"])

    def test_vagamod_candidates_accepted(self):
        resp, ddb = self._post(_producer(kind="reconciliation", source_principal="vagamod-prod",
                                         proposedCalls=None, candidates=CANDS))
        self.assertEqual(201, resp["statusCode"], resp["body"])
        self.assertEqual("vagamod", json.loads(resp["body"])["source"])
        self.assertEqual(CANDS, json.loads(self._stored(ddb)["candidates"]["S"]))

    def test_stored_producer_card_reads_back_with_parsed_calls_and_state(self):
        _, ddb = self._post(_producer(subject={"record_id": "run:42", "project": "enceladus", "version": "x"}))
        public = self.lf._escalation_public(self._stored(ddb))
        self.assertEqual([CALL], public["proposedCalls"])
        self.assertEqual("run:42", public["subject"]["record_id"])
        self.assertEqual(("tool_call", "pending"), (public["kind"], public["state"]))

    def test_telemetry_kinds_accepted_without_actions(self):
        for kind, ttl in (("notice", gate.dt.timedelta(days=7)), ("drift", None)):
            with self.subTest(kind=kind):
                resp, ddb = self._post(_producer(kind=kind, proposedCalls=None))
                self.assertEqual(201, resp["statusCode"], resp["body"])
                body = json.loads(resp["body"])
                self.assertEqual("telemetry", body["family"])
                self.assertEqual("auto_clear", body["onExpire"])
                self.assertEqual(gate._z(NOW + ttl) if ttl else None, body["expiresAt"])
                self.assertEqual("pending", self.lf._escalation_public(self._stored(ddb))["state"])

    def test_telemetry_with_an_action_is_refused(self):
        for extra in ({"proposedCalls": [dict(CALL)]}, {"proposedCalls": None, "candidates": CANDS}):
            resp, ddb = self._post(_producer(kind="drift", **extra))
            self.assertEqual(400, resp["statusCode"])
            ddb.put_item.assert_not_called()

    def test_shared_principal_needs_a_source_to_disambiguate(self):
        resp, _ = self._post(_producer(source_principal="shared"))
        self.assertEqual(403, resp["statusCode"])
        resp, _ = self._post(_producer(source_principal="shared", source="vagamod"))
        self.assertEqual(201, resp["statusCode"], resp["body"])


class TestProducerRefuse(_ProducerBase):
    def _refused(self, body, code):
        resp, ddb = self._post(body)
        self.assertEqual(code, resp["statusCode"], resp["body"])
        ddb.put_item.assert_not_called()

    def test_exactly_one_of_proposed_calls_or_candidates(self):
        self._refused(_producer(candidates=CANDS), 400)  # both
        self._refused(_producer(proposedCalls=None), 400)  # neither

    def test_unlisted_or_missing_principal_is_refused(self):
        self._refused(_producer(source_principal="intruder"), 403)
        self._refused(_producer(source_principal=None, source="think"), 400)

    def test_principal_listed_for_another_source_is_refused(self):
        self._refused(_producer(source="vagamod"), 403)  # think-prod is only a think principal

    def test_allow_list_fails_closed_when_unset_or_malformed(self):
        for raw in ("", "not-json", "[]", '{"think": "think-prod"}'):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"GATE_PRODUCER_PRINCIPALS": raw}):
                self._refused(_producer(), 403)

    def test_principal_is_checked_before_body_validation(self):
        self._refused(_producer(source_principal="intruder", kind="bogus"), 403)

    def test_malformed_resolved_calls_are_refused(self):
        bad = [dict(CALL, callHash="XYZ"), dict(CALL, method="GET"), dict(CALL, args=[]),
               dict(CALL, extra=1), {k: v for k, v in CALL.items() if k != "ifMatch"}]
        for call in bad:
            with self.subTest(call=call):
                self._refused(_producer(proposedCalls=[call]), 400)
        self._refused(_producer(proposedCalls=[]), 400)
        self._refused(_producer(proposedCalls=None, candidates=[{"id": "a", "label": "A", "call": {"x": 1}}]), 400)


class TestLegacyUnchanged(_ProducerBase):
    def test_legacy_mutation_request_is_still_accepted(self):
        resp, ddb = self._request(_request_body())
        self.assertEqual(201, resp["statusCode"], resp["body"])
        self.assertEqual("deploy_arc_change", json.loads(resp["body"])["mutation_type"])
        self.assertEqual("deploy_arc_change", ddb.put_item.call_args.kwargs["Item"]["mutation_type"]["S"])

    def test_legacy_telemetry_kind_is_still_refused(self):
        resp, _ = self._request(_request_body(kind="drift"))
        self.assertEqual(400, resp["statusCode"])

    def test_legacy_request_cannot_carry_proposed_calls(self):
        resp, _ = self._request(_request_body(proposedCalls=[dict(CALL)]))
        self.assertEqual(400, resp["statusCode"])

    def test_legacy_claimed_principal_is_verified(self):
        resp, _ = self._request(_request_body(source_principal="intruder"))
        self.assertEqual(403, resp["statusCode"])

    def test_missing_mutation_type_without_producer_marker_keeps_the_legacy_error(self):
        resp, _ = self._request(_request_body(mutation_type=""))
        self.assertEqual(400, resp["statusCode"])
        self.assertIn("Unknown mutation_type", json.loads(resp["body"])["error"])


if __name__ == "__main__":
    unittest.main()
