"""DVP-TSK-A17 part 2 (E4-R18): HubExchange principals may CREATE producer escalations.

The source principal is DERIVED from the token's issuer name (HUB_EXCHANGE_PRODUCERS), never
client-claimed; only kinds tool_call / reconciliation / drift / notice are allowed; the existing
producer validation still applies; every non-exchange path is unchanged.
"""
import json
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

from enceladus_shared import hub_exchange as hx  # noqa: E402
import test_escalation_gate_e4 as gate  # noqa: E402

ISSUERS = [
    {"name": "vagamod-keycloak", "iss": "https://auth.vagamod.example/realms/vagamod",
     "jwks_uri": "https://auth.vagamod.example/certs", "audiences": ["vagamod-shell"]},
    {"name": "coach-cognito", "iss": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_COACH",
     "jwks_uri": "https://cognito-idp.example/coach.json", "audiences": ["coach-client"]},
    {"name": "rogue-idp", "iss": "https://rogue.example", "jwks_uri": "https://rogue.example/jwks",
     "audiences": ["x"]},
]
ENV = {
    "HUB_EXCHANGE_ISSUERS": json.dumps(ISSUERS), "HUB_EXCHANGE_SECRET_ARN": "arn:test:secret",
    "HUB_SHELL_ORIGINS": "https://coach.thepup.io,https://think.example.io,https://vagamod.com",
    "ESCALATION_MACHINE_EMAIL_DOMAINS": "enceladus.internal",
    "GATE_PRODUCER_PRINCIPALS": json.dumps({"vagamod": ["vagamod"], "think": ["think"], "coach": ["coach"]}),
}
CALL = {
    "capability": "tracker.set", "method": "POST", "path": "/enceladus/task/ENC-TSK-J10",
    "args": {"field": "title"}, "annotations": {"readOnlyHint": False, "destructiveHint": False},
    "ifMatch": "3", "callHash": "a" * 64,
}
AUTH_TIME = int(time.time()) - 120


def _body(**overrides):
    body = {"kind": "tool_call", "title": "Run the promote", "proposedCalls": [dict(CALL)]}
    body.update(overrides)
    return {k: v for k, v in body.items() if v is not None}


class _HubBase(gate._Base):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, ENV)
        env.start()
        self.addCleanup(env.stop)
        sec = mock.patch.object(hx, "_fetch_secret", return_value="s" * 64)
        sec.start()
        self.addCleanup(sec.stop)
        hx._secret_cache.update({"value": None, "fetched_at": 0.0})
        self.addCleanup(hx._secret_cache.update, {"value": None, "fetched_at": 0.0})

    def token(self, issuer=0, email="io@jreese.net", now=None, acr="2"):
        return hx.mint_hub_token(sub="u1", email=email, src_iss=ISSUERS[issuer]["iss"],
                                 src_name=ISSUERS[issuer]["name"], auth_time=AUTH_TIME, acr=acr,
                                 now=now)["hub_token"]

    def claims(self, **kw):
        return hx.principal_claims(hx.verify_hub_token(self.token(**kw)))

    def _post(self, body, hub):
        ddb = mock.MagicMock()
        with mock.patch.object(self.lf, "_get_ddb", return_value=ddb), \
             mock.patch.object(self.lf, "_get_project_prefix", return_value="ENC"), \
             mock.patch.object(self.lf, "_next_record_id", return_value="ENC-ESC-902"), \
             mock.patch.object(self.lf, "_notify_escalation_event"):
            resp = self.lf._handle_escalation_request("enceladus", body, hub=hub)
        return resp, ddb

    def _route(self, headers, body=None, method="POST", origin=None):
        path = next(p for p in ("/api/v1/tracker/enceladus/escalation", "/enceladus/escalation",
                                "/api/v1/tracker/enceladus/escalation/")
                    if self.lf._RE_ESCALATION.match(p))
        hdrs = dict(headers)
        if origin:
            hdrs["origin"] = origin
        event = {"requestContext": {"http": {"method": method}}, "rawPath": path, "headers": hdrs,
                 "body": json.dumps(body) if body is not None else None}
        ddb = mock.MagicMock()
        with mock.patch.object(self.lf, "_validate_project_exists", return_value=None), \
             mock.patch.object(self.lf, "_get_ddb", return_value=ddb), \
             mock.patch.object(self.lf, "_get_project_prefix", return_value="ENC"), \
             mock.patch.object(self.lf, "_next_record_id", return_value="ENC-ESC-903"), \
             mock.patch.object(self.lf, "_notify_escalation_event"):
            return self.lf.lambda_handler(event, None), ddb


class TestHubProducerCreate(_HubBase):
    def test_tool_call_created_with_derived_principal_and_initiator(self):
        resp, ddb = self._post(_body(), self.claims())
        self.assertEqual(201, resp["statusCode"], resp["body"])
        item = ddb.put_item.call_args.kwargs["Item"]
        self.assertEqual("vagamod", item["requested_by"]["M"]["session_id"]["S"])  # human can still decide
        self.assertEqual("vagamod", item["source"]["S"])
        self.assertEqual("io@jreese.net", item["initiated_by"]["S"])
        self.assertEqual("vagamod-keycloak", item["hub_source"]["S"])
        evidence = {e["label"]: e["ref"] for e in json.loads(item["evidence"]["S"])}
        self.assertEqual(str(AUTH_TIME), evidence["hub_exchange_auth_time"])
        self.assertEqual("2", evidence["hub_exchange_acr"])
        self.assertEqual("vagamod-keycloak", evidence["hub_exchange_issuer"])

    def test_other_issuer_derives_its_own_principal_and_notice_kind_is_allowed(self):
        resp, ddb = self._post({"kind": "notice", "title": "FYI"}, self.claims(issuer=1))
        self.assertEqual(201, resp["statusCode"], resp["body"])
        item = ddb.put_item.call_args.kwargs["Item"]
        self.assertEqual(("coach", "coach"), (item["requested_by"]["M"]["session_id"]["S"], item["source"]["S"]))

    def test_matching_claimed_principal_is_accepted_mismatch_is_403(self):
        ok, _ = self._post(_body(source_principal="vagamod"), self.claims())
        self.assertEqual(201, ok["statusCode"], ok["body"])
        for claimed in ("think", "recipe-runner", "vagamod-prod"):
            resp, ddb = self._post(_body(source_principal=claimed), self.claims())
            self.assertEqual(403, resp["statusCode"], claimed)
            ddb.put_item.assert_not_called()
        resp, _ = self._post(_body(sourcePrincipal="think"), self.claims())
        self.assertEqual(403, resp["statusCode"])

    def test_disallowed_kinds_and_legacy_mutation_are_403(self):
        for body in (_body(kind="escalation"), _body(kind=None),
                     {"mutation_type": "set_field", "target_record_id": "ENC-TSK-J10", "payload": {"a": 1},
                      "justification": "x", "kind": "tool_call"}):
            resp, ddb = self._post(body, self.claims())
            self.assertEqual(403, resp["statusCode"], body)
            ddb.put_item.assert_not_called()

    def test_unmapped_issuer_is_403_and_malformed_map_fails_closed(self):
        with mock.patch.dict(os.environ, {"HUB_EXCHANGE_PRODUCERS": json.dumps({"coach-cognito": "coach"})}):
            self.assertEqual(403, self._post(_body(), self.claims())[0]["statusCode"])
            self.assertEqual(201, self._post(_body(), self.claims(issuer=1))[0]["statusCode"])
        with mock.patch.dict(os.environ, {"HUB_EXCHANGE_PRODUCERS": "not json"}):
            self.assertEqual(403, self._post(_body(), self.claims())[0]["statusCode"])
        self.assertEqual(403, self._post(_body(), self.claims(issuer=2))[0]["statusCode"])  # rogue-idp unmapped

    def test_producer_validation_still_applies(self):
        both = _body(candidates=[{"id": "a", "label": "A"}, {"id": "b", "label": "B"}])
        resp, _ = self._post(both, self.claims())
        self.assertEqual(400, resp["statusCode"])
        resp, _ = self._post(_body(proposedCalls=[{"capability": "x"}]), self.claims())
        self.assertEqual(400, resp["statusCode"])

    def test_client_cannot_spoof_the_assurance_evidence(self):
        spoof = _body(evidence=[{"label": "hub_exchange_acr", "ref": "9"}, {"label": "note", "ref": "n"}])
        resp, ddb = self._post(spoof, self.claims())
        self.assertEqual(201, resp["statusCode"], resp["body"])
        evidence = json.loads(ddb.put_item.call_args.kwargs["Item"]["evidence"]["S"])
        self.assertEqual(["2"], [e["ref"] for e in evidence if e["label"] == "hub_exchange_acr"])
        self.assertIn("note", [e["label"] for e in evidence])


class TestHubRouter(_HubBase):
    def test_valid_token_creates_and_echoes_only_a_shell_origin(self):
        auth = {"authorization": f"HubExchange {self.token()}"}
        resp, ddb = self._route(auth, _body(), origin="https://vagamod.com")
        self.assertEqual(201, resp["statusCode"], resp["body"])
        self.assertEqual("https://vagamod.com", resp["headers"]["Access-Control-Allow-Origin"])
        self.assertIn("Authorization", resp["headers"]["Access-Control-Allow-Headers"])
        self.assertEqual("vagamod", ddb.put_item.call_args.kwargs["Item"]["requested_by"]["M"]["session_id"]["S"])
        evil, _ = self._route(auth, _body(), origin="https://evil.example")
        self.assertNotEqual("https://evil.example", evil["headers"]["Access-Control-Allow-Origin"])

    def test_preflight_admits_shell_origin_only(self):
        ok, _ = self._route({}, method="OPTIONS", origin="https://think.example.io")
        self.assertEqual("https://think.example.io", ok["headers"]["Access-Control-Allow-Origin"])
        bad, _ = self._route({}, method="OPTIONS", origin="https://evil.example")
        self.assertNotEqual("https://evil.example", bad["headers"]["Access-Control-Allow-Origin"])

    def test_expired_forged_empty_and_unknown_tokens_are_refused(self):
        good = self.token()
        head, payload, sig = good.split(".")
        expired = self.token(now=int(time.time()) - 3600)
        for token, want in ((expired, 401), (f"{head}.{payload}.{sig[:-2]}AA", 401), ("", 401), ("a.b.c", 401)):
            resp, ddb = self._route({"authorization": f"HubExchange {token}".strip()}, _body())
            self.assertEqual(want, resp["statusCode"], token[:12])
            ddb.put_item.assert_not_called()
        with mock.patch.dict(os.environ, {"HUB_EXCHANGE_ISSUERS": json.dumps(ISSUERS[1:])}):
            resp, _ = self._route({"authorization": f"HubExchange {good}"}, _body())
            self.assertEqual(401, resp["statusCode"])  # issuer removed from the allow-list
        machine = self.token(email="runner@enceladus.internal")
        resp, _ = self._route({"authorization": f"HubExchange {machine}"}, _body())
        self.assertIn(resp["statusCode"], (401, 403))

    def test_hub_token_is_refused_on_every_other_escalation_route(self):
        auth = {"authorization": f"HubExchange {self.token()}"}
        resp, _ = self._route(auth, method="GET")
        self.assertEqual(403, resp["statusCode"])

    def test_non_exchange_paths_are_unchanged(self):
        with mock.patch.object(self.lf, "COORDINATION_INTERNAL_API_KEYS", {"k1"}):
            resp, ddb = self._route({"x-coordination-internal-key": "k1"},
                                    _body(source_principal="think"))
        self.assertEqual(201, resp["statusCode"], resp["body"])
        item = ddb.put_item.call_args.kwargs["Item"]
        self.assertNotIn("initiated_by", item)
        self.assertEqual("think", item["requested_by"]["M"]["session_id"]["S"])
        anon, _ = self._route({}, _body())
        self.assertEqual(401, anon["statusCode"])


if __name__ == "__main__":
    unittest.main()
