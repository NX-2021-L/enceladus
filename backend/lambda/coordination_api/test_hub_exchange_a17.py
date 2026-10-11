"""DVP-TSK-A17 (DVP-PLN-013 E4-W2.8, ruling E4-R14): hub token exchange.

Exchange refusals, the hub principal on decide / list, route confinement,
step-up assurance from the source auth_time, and shell-origin CORS.
"""
import datetime as dt
import json
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

import jwt  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from jwt.algorithms import RSAAlgorithm  # noqa: E402

from enceladus_shared import hub_exchange as hx  # noqa: E402
from test_escalation_decide_hardening_e4 import _decide, _entries  # noqa: E402
from test_escalation_decision_j70 import _escalation_item, coordination_lambda as coord  # noqa: E402

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PEM = _KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())
_JWK = json.loads(RSAAlgorithm.to_jwk(_KEY.public_key()))
_JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})
ISSUERS = [
    {"name": "vagamod-keycloak", "iss": "https://auth.vagamod.example/realms/vagamod",
     "jwks_uri": "https://auth.vagamod.example/realms/vagamod/protocol/openid-connect/certs",
     "audiences": ["vagamod-shell"]},
    {"name": "coach-cognito", "iss": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_COACH",
     "jwks_uri": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_COACH/.well-known/jwks.json",
     "audiences": ["coach-client"]},
    {"name": "think-iograph", "iss": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_THINK",
     "jwks_uri": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_THINK/.well-known/jwks.json",
     "audiences": ["think-client"]},
]
ENV = {"HUB_EXCHANGE_ISSUERS": json.dumps(ISSUERS), "COORDINATION_INTERNAL_API_KEY": "k" * 64,
       "HUB_SHELL_ORIGINS": "https://coach.thepup.io,https://think.example.io,https://vagamod.com",
       "ESCALATION_MACHINE_EMAIL_DOMAINS": "enceladus.internal"}
ALLOW = {"io@jreese.net"}


def src_token(issuer=0, drop=(), key=None, headers=None, **over):
    cfg = ISSUERS[issuer]
    now = int(time.time())
    claims = {"iss": cfg["iss"], "aud": cfg["audiences"][0], "sub": "u-1", "email": "io@jreese.net",
              "email_verified": True, "auth_time": now - 60, "iat": now - 60, "exp": now + 3600, "acr": "1"}
    claims.update(over)
    for name in drop:
        claims.pop(name, None)
    return jwt.encode(claims, key or _PEM, algorithm="RS256", headers=headers or {"kid": "k1"})


def api_event(method, path, headers=None, body=None):
    return {"requestContext": {"http": {"method": method, "path": path}, "stage": "$default"},
            "rawPath": path, "path": path, "httpMethod": method, "headers": headers or {},
            "body": json.dumps(body) if body is not None else None}


class HubBase(unittest.TestCase):
    def setUp(self):
        patches = [
            mock.patch.dict(os.environ, ENV),
            mock.patch.object(hx, "_fetch_jwks", return_value={"keys": [_JWK]}),
            mock.patch.object(coord, "_load_escalation_approver_allowlist", return_value=set(ALLOW)),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        hx._secret_cache.update({"value": None, "fetched_at": 0.0})
        hx._jwks_cache.clear()
        coord._request_cors["origin"] = None

    def exchange(self, token, origin=None):
        headers = {"origin": origin} if origin else {}
        return coord.lambda_handler(api_event("POST", "/api/v1/coordination/hub/exchange", headers,
                                              {"id_token": token}), None)

    def hub_token(self, **over):
        resp = self.exchange(src_token(**over))
        self.assertEqual(200, resp["statusCode"], resp["body"])
        return json.loads(resp["body"])["hub_token"]


class TestExchange(HubBase):
    def test_each_allow_listed_issuer_mints_a_short_lived_principal(self):
        for idx, cfg in enumerate(ISSUERS):
            with self.subTest(issuer=cfg["name"]):
                now = int(time.time())
                resp = self.exchange(src_token(issuer=idx, auth_time=now - 120))
                self.assertEqual(200, resp["statusCode"], resp["body"])
                out = json.loads(resp["body"])
                self.assertLessEqual(out["expires_at"] - now, hx.MAX_TTL_SECONDS + 5)
                self.assertEqual(now - 120, out["auth_time"])
                self.assertEqual("1", out["acr"])
                claims = hx.verify_hub_token(out["hub_token"])
                self.assertEqual(cfg["iss"], claims["src_iss"])
                self.assertEqual("hub_exchange", claims["kind"])
                self.assertEqual(now - 120, claims["auth_time"])
                self.assertEqual("io@jreese.net", claims["email"])

    def test_unknown_issuer_is_refused_without_detail(self):
        resp = self.exchange(src_token(iss="https://evil.example/realms/x"))
        self.assertEqual(401, resp["statusCode"])
        self.assertNotIn("evil", resp["body"])
        self.assertNotIn("vagamod", resp["body"])

    def test_unknown_identity_is_refused(self):
        resp = self.exchange(src_token(email="stranger@example.com"))
        self.assertEqual(403, resp["statusCode"])
        self.assertNotIn("stranger", resp["body"])

    def test_expired_token_is_refused(self):
        self.assertEqual(401, self.exchange(src_token(exp=int(time.time()) - 600))["statusCode"])

    def test_wrong_audience_and_forged_signature_are_refused(self):
        self.assertEqual(401, self.exchange(src_token(aud="someone-elses-client"))["statusCode"])
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.assertEqual(401, self.exchange(src_token(key=other))["statusCode"])
        forged = jwt.encode({"iss": ISSUERS[0]["iss"], "aud": "vagamod-shell", "exp": int(time.time()) + 99},
                            "x" * 48, algorithm="HS256", headers={"kid": "k1"})
        self.assertEqual(401, self.exchange(forged)["statusCode"])

    def test_client_credentials_and_non_id_tokens_can_never_be_exchanged(self):
        self.assertEqual(401, self.exchange(src_token(token_use="access"))["statusCode"])
        self.assertEqual(401, self.exchange(src_token(typ="Bearer"))["statusCode"])
        svc = src_token(drop=("email",), preferred_username="service-account-agent", clientId="agent")
        self.assertEqual(401, self.exchange(svc)["statusCode"])
        self.assertEqual(401, self.exchange(src_token(drop=("aud",), client_id="m2m"))["statusCode"])
        # a machine-domain identity is refused even if someone put it on the allow-list
        with mock.patch.object(coord, "_load_escalation_approver_allowlist",
                               return_value={"terminal-agent@enceladus.internal"}):
            resp = self.exchange(src_token(email="terminal-agent@enceladus.internal"))
        self.assertEqual(403, resp["statusCode"])

    def test_missing_auth_time_is_refused_not_defaulted_to_iat(self):
        self.assertEqual(401, self.exchange(src_token(drop=("auth_time",)))["statusCode"])

    def test_empty_issuer_config_fails_closed(self):
        with mock.patch.dict(os.environ, {"HUB_EXCHANGE_ISSUERS": "[]"}):
            self.assertEqual(401, self.exchange(src_token())["statusCode"])
        with mock.patch.dict(os.environ, {"HUB_EXCHANGE_ISSUERS": "not json"}):
            self.assertEqual(401, self.exchange(src_token())["statusCode"])

    def test_body_without_id_token_is_400(self):
        resp = coord.lambda_handler(api_event("POST", "/api/v1/coordination/hub/exchange", {}, {}), None)
        self.assertEqual(400, resp["statusCode"])


class TestHubPrincipal(HubBase):
    def test_decide_accepts_the_exchanged_principal_and_records_hub_auth_method(self):
        now = int(time.time())
        token = self.hub_token(auth_time=now - 90)
        claims = hx.principal_claims(hx.verify_hub_token(token))
        resp, ddb, invoke = _decide(_escalation_item(), claims=claims)
        self.assertEqual(200, resp["statusCode"], resp["body"])
        logged = _entries(ddb)
        self.assertTrue(logged)
        self.assertEqual("hub_exchange:vagamod-keycloak", logged[-1]["auth_method"])
        self.assertEqual("aal1", logged[-1]["assurance"])
        self.assertEqual(coord._gate_epoch_to_ts(now - 90), logged[-1]["auth_time"])

    def test_decide_invariants_still_refuse_non_allow_listed_and_malformed_hub_claims(self):
        base = hx.principal_claims(hx.verify_hub_token(self.hub_token()))
        resp, _, invoke = _decide(_escalation_item(), claims=dict(base, email="other@example.com"))
        self.assertEqual(403, resp["statusCode"])
        invoke.assert_not_called()
        for bad in (dict(base, kind="x"), dict(base, token_use="access"), dict(base, auth_method="interactive_human"),
                    dict(base, email="agent@enceladus.internal")):
            resp, _, invoke = _decide(_escalation_item(), claims=bad)
            self.assertEqual(403, resp["statusCode"], bad)
            invoke.assert_not_called()

    def test_assurance_is_derived_from_the_source_auth_time(self):
        now = dt.datetime.now(dt.timezone.utc)
        fresh = int(now.timestamp()) - 60
        claims = hx.principal_claims(hx.verify_hub_token(self.hub_token(auth_time=fresh)))
        ev, err = coord._escalation_auth_evidence(claims, {}, now)
        self.assertEqual(("aal1", "hub_exchange:vagamod-keycloak"), (ev["assurance"], ev["auth_method"]))
        ev, err = coord._escalation_auth_evidence(claims, {"stepUp": {"method": "cognito_max_age", "auth_time": fresh}}, now)
        self.assertEqual("", err)
        self.assertEqual("aal2", ev["assurance"])
        _, err = coord._escalation_auth_evidence(claims, {"stepUp": {"method": "cognito_max_age", "auth_time": fresh - 5}}, now)
        self.assertIn("does not match", err)
        stale = int(now.timestamp()) - 4000
        old = hx.principal_claims(hx.verify_hub_token(self.hub_token(auth_time=stale)))
        _, err = coord._escalation_auth_evidence(old, {"stepUp": {"method": "cognito_max_age", "auth_time": stale}}, now)
        self.assertIn("stale", err)

    def test_list_and_decide_routes_accept_hub_authorization(self):
        auth = {"authorization": f"HubExchange {self.hub_token()}"}
        with mock.patch.object(coord, "_handle_escalations_feed", return_value={"statusCode": 200, "body": "{}"}) as feed:
            resp = coord.lambda_handler(api_event("GET", "/api/v1/coordination/escalations", auth), None)
        self.assertEqual(200, resp["statusCode"])
        self.assertEqual("hub_exchange", feed.call_args.args[1]["auth_mode"])
        with mock.patch.object(coord, "_handle_escalation_decision", return_value={"statusCode": 200, "body": "{}"}) as dec:
            resp = coord.lambda_handler(
                api_event("POST", "/api/v1/coordination/escalations/enceladus/ENC-ESC-001/approve", auth, {}), None)
        self.assertEqual(200, resp["statusCode"])
        self.assertEqual("io@jreese.net", dec.call_args.args[4]["email"])

    def test_hub_principal_is_confined_to_the_human_hub_routes(self):
        auth = {"authorization": f"HubExchange {self.hub_token()}"}
        for method, path in (("GET", "/api/v1/coordination/escalations/watch"),
                             ("POST", "/api/v1/coordination/mcp"),
                             ("GET", "/api/v1/coordination/components"),
                             ("POST", "/api/v1/coordination/components/comp-x/approve")):
            with self.subTest(path=path):
                self.assertEqual(403, coord.lambda_handler(api_event(method, path, auth), None)["statusCode"])

    def test_expired_tampered_rotated_and_revoked_hub_tokens_are_refused(self):
        feed = api_event("GET", "/api/v1/coordination/escalations")
        def call(token):
            ev = dict(feed, headers={"authorization": f"HubExchange {token}"})
            return coord.lambda_handler(ev, None)["statusCode"]
        good = self.hub_token()
        minted = hx.mint_hub_token(sub="u", email="io@jreese.net", src_iss=ISSUERS[0]["iss"],
                                   src_name="vagamod-keycloak", auth_time=int(time.time()) - 60,
                                   acr="1", now=int(time.time()) - 3600)
        self.assertEqual(401, call(minted["hub_token"]))              # expired hub token
        head, payload, sig = good.split(".")
        self.assertEqual(401, call(f"{head}.{payload}.{sig[:-2]}AA"))  # tampered signature
        self.assertEqual(401, call(""))                                # empty HubExchange token
        with mock.patch.dict(os.environ, {"COORDINATION_INTERNAL_API_KEY": "r" * 64}):
            self.assertEqual(401, call(good))                          # signing key rotated, no PREVIOUS
        with mock.patch.dict(os.environ, {"HUB_EXCHANGE_ISSUERS": json.dumps(ISSUERS[1:])}):
            self.assertEqual(401, call(good))                          # issuer removed from allow-list


class TestCors(HubBase):
    def test_only_the_shell_origins_are_admitted_on_exchange_list_and_decide(self):
        paths = ("/api/v1/coordination/hub/exchange", "/api/v1/coordination/escalations",
                 "/api/v1/coordination/escalations/enceladus/ENC-ESC-001/approve")
        for path in paths:
            for origin in ("https://coach.thepup.io", "https://think.example.io", "https://vagamod.com"):
                with self.subTest(path=path, origin=origin):
                    resp = coord.lambda_handler(api_event("OPTIONS", path, {"origin": origin}), None)
                    self.assertEqual(origin, resp["headers"]["Access-Control-Allow-Origin"])
                    self.assertEqual("Origin", resp["headers"]["Vary"])
            for origin in ("https://evil.example", "https://vagamod.com.evil.example", "http://vagamod.com"):
                with self.subTest(path=path, denied=origin):
                    resp = coord.lambda_handler(api_event("OPTIONS", path, {"origin": origin}), None)
                    self.assertEqual(coord.CORS_ORIGIN, resp["headers"]["Access-Control-Allow-Origin"])

    def test_other_routes_keep_the_single_enceladus_origin(self):
        resp = coord.lambda_handler(api_event("OPTIONS", "/api/v1/coordination/components",
                                              {"origin": "https://vagamod.com"}), None)
        self.assertEqual(coord.CORS_ORIGIN, resp["headers"]["Access-Control-Allow-Origin"])

    def test_exchange_response_carries_the_shell_origin(self):
        resp = self.exchange(src_token(), origin="https://coach.thepup.io")
        self.assertEqual("https://coach.thepup.io", resp["headers"]["Access-Control-Allow-Origin"])
        self.assertEqual("https://coach.thepup.io",
                         self.exchange(src_token(email="no@example.com"), origin="https://coach.thepup.io")
                         ["headers"]["Access-Control-Allow-Origin"])


class TestHubKeyDerivation(unittest.TestCase):
    """E4-R20: the HMAC key is derived from COORDINATION_INTERNAL_API_KEY (no Secrets Manager)."""

    def setUp(self):
        env = mock.patch.dict(os.environ, ENV)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("COORDINATION_INTERNAL_API_KEY_PREVIOUS", None)
        os.environ.pop("HUB_EXCHANGE_SECRET_ARN", None)

    def mint(self, **kw):
        return hx.mint_hub_token(sub="u", email="io@jreese.net", src_iss=ISSUERS[0]["iss"],
                                 src_name="vagamod-keycloak", auth_time=int(time.time()) - 60,
                                 acr="1", **kw)["hub_token"]

    def test_signature_is_hmac_of_the_derived_key(self):
        import base64
        import hashlib
        import hmac as _hmac
        token = self.mint()
        head, payload, sig = token.split(".")
        derived = _hmac.new(b"k" * 64, b"enceladus-hub-exchange-v1", hashlib.sha256).digest()
        want = base64.urlsafe_b64encode(
            _hmac.new(derived, f"{head}.{payload}".encode("ascii"), hashlib.sha256).digest()).rstrip(b"=").decode()
        self.assertEqual(want, sig)

    def test_token_minted_with_previous_key_still_verifies_during_rotation(self):
        old = self.mint()
        with mock.patch.dict(os.environ, {"COORDINATION_INTERNAL_API_KEY": "n" * 64}):
            with self.assertRaises(hx.HubExchangeError) as ctx:  # no PREVIOUS: rotated away
                hx.verify_hub_token(old)
            self.assertEqual(401, ctx.exception.status)
            with mock.patch.dict(os.environ, {"COORDINATION_INTERNAL_API_KEY_PREVIOUS": "k" * 64}):
                self.assertEqual("io@jreese.net", hx.verify_hub_token(old)["email"])  # rotation window
                fresh = self.mint()  # minted with the CURRENT key
                self.assertEqual("io@jreese.net", hx.verify_hub_token(fresh)["email"])
            with self.assertRaises(hx.HubExchangeError):  # fresh token is not valid under the old key alone
                with mock.patch.dict(os.environ, {"COORDINATION_INTERNAL_API_KEY": "k" * 64}):
                    hx.verify_hub_token(fresh)

    def test_missing_key_fails_closed_on_mint_and_verify(self):
        token = self.mint()
        with mock.patch.dict(os.environ, {"COORDINATION_INTERNAL_API_KEY": ""}):
            for call in (self.mint, lambda: hx.verify_hub_token(token)):
                with self.assertRaises(hx.HubExchangeError) as ctx:
                    call()
                self.assertEqual(503, ctx.exception.status)

    def test_secret_arn_is_only_an_optional_override(self):
        with mock.patch.dict(os.environ, {"HUB_EXCHANGE_SECRET_ARN": "arn:test:secret"}), \
             mock.patch.object(hx, "_fetch_secret", return_value="s" * 64):
            hx._secret_cache.update({"value": None, "fetched_at": 0.0})
            token = self.mint()
            self.assertEqual("io@jreese.net", hx.verify_hub_token(token)["email"])
        hx._secret_cache.update({"value": None, "fetched_at": 0.0})
        with self.assertRaises(hx.HubExchangeError):  # override key != derived key
            hx.verify_hub_token(token)


if __name__ == "__main__":
    unittest.main()
