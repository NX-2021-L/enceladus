"""Tests for the component-registry decider guard (ENC-TSK-S82 slice 1, closes ENC-ISS-805).

Every io-only component mutation refuses internal-key, managed-token and machine
Cognito principals (403 COMPONENT_DECIDER_REQUIRED); an allowlisted human passes.
Reuses the module-load pattern of test_components_propose.py.
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
coordination_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = coordination_lambda
_SPEC.loader.exec_module(coordination_lambda)

HUMAN_CLIENT = "human-pwa-client"
HUMAN_EMAIL = "io@example.com"

HUMAN_CLAIMS = {
    "auth_mode": "cognito", "token_use": "id", "aud": HUMAN_CLIENT,
    "email": HUMAN_EMAIL, "sub": "sub-io",
}
NOT_ALLOWLISTED_HUMAN = dict(HUMAN_CLAIMS, email="someone-else@example.com")
MACHINE_COGNITO = dict(HUMAN_CLAIMS, email="terminal-agent@enceladus.internal", sub="sub-machine")
ACCESS_TOKEN = {"auth_mode": "cognito", "token_use": "access", "client_id": HUMAN_CLIENT, "email": HUMAN_EMAIL}
INTERNAL_KEY = {"auth_mode": "internal-key", "sub": "agent"}
MANAGED_TOKEN = {"auth_mode": "managed-token", "sub": "agent"}
NO_AUTH_MODE = {"sub": "agent"}

REFUSED = {
    "internal-key": INTERNAL_KEY,
    "managed-token": MANAGED_TOKEN,
    "machine-cognito": MACHINE_COGNITO,
    "access-token": ACCESS_TOKEN,
    "non-allowlisted-human": NOT_ALLOWLISTED_HUMAN,
    "no-auth-mode": NO_AUTH_MODE,
}


def _event(body=None):
    return {"body": json.dumps(body or {}), "headers": {}}


def _guarded_calls(L):
    """(name, callable(claims)) for every handler the guard covers (advance is covered by a source check)."""
    cid = "comp-x"
    return [
        ("create", lambda c: L._handle_components_create(_event({"component_name": "X"}), c)),
        ("approve", lambda c: L._handle_components_approve(cid, _event(), c)),
        ("reject", lambda c: L._handle_components_reject(cid, _event({"rejection_reason": "long enough reason"}), c)),
        ("revert", lambda c: L._handle_components_revert(cid, _event(), c)),
        ("deprecate", lambda c: L._handle_components_deprecate(cid, _event(), c)),
        ("restore", lambda c: L._handle_components_restore(cid, _event(), c)),
        ("delete", lambda c: L._handle_components_delete(cid, _event(), c)),
    ] + [
        (f"update:{f}", lambda c, f=f: L._handle_components_update(cid, _event({f: "x"}), c))
        for f in ("transition_type", "required_transition_type", "lifecycle_status", "status", "project_id", "component_id")
    ]


def _body(resp):
    body = json.loads(resp.get("body") or "{}")
    # Surface the envelope code as a top-level "code" for assertions.
    body.setdefault("code", (body.get("error_envelope") or {}).get("code"))
    return body


class ComponentDeciderGuardTests(unittest.TestCase):
    def setUp(self):
        L = coordination_lambda
        patches = [
            mock.patch.object(L, "_load_escalation_approver_allowlist", return_value={HUMAN_EMAIL}),
            mock.patch.object(L, "_escalation_human_client_ids", return_value={HUMAN_CLIENT}),
            mock.patch.object(L, "CHECKOUT_ASSISTANT_KEY", "assistant-key"),
            mock.patch.object(L, "ENABLE_COMPONENT_PROPOSAL", True),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_helper_passes_only_allowlisted_human(self):
        L = coordination_lambda
        self.assertIsNone(L._require_component_decider(HUMAN_CLAIMS))
        for name, claims in REFUSED.items():
            with self.subTest(principal=name):
                resp = L._require_component_decider(claims)
                self.assertEqual(resp["statusCode"], 403)
                self.assertEqual(_body(resp).get("code"), "COMPONENT_DECIDER_REQUIRED")

    def test_allowlist_fetch_failure_fails_closed(self):
        L = coordination_lambda
        with mock.patch.object(L, "_load_escalation_approver_allowlist", return_value=set()):
            self.assertEqual(L._require_component_decider(HUMAN_CLAIMS)["statusCode"], 403)

    def test_every_guarded_handler_refuses_non_decider_principals(self):
        L = coordination_lambda
        with mock.patch.object(L, "_get_ddb") as ddb:
            for name, call in _guarded_calls(L):
                for pname, claims in REFUSED.items():
                    with self.subTest(handler=name, principal=pname):
                        resp = call(claims)
                        self.assertEqual(resp["statusCode"], 403)
                        self.assertEqual(_body(resp).get("code"), "COMPONENT_DECIDER_REQUIRED")
            ddb.return_value.update_item.assert_not_called()
            ddb.return_value.put_item.assert_not_called()
            ddb.return_value.delete_item.assert_not_called()
            ddb.return_value.transact_write_items.assert_not_called()

    def test_allowlisted_human_is_not_refused_by_the_guard(self):
        L = coordination_lambda
        with mock.patch.object(L, "_get_ddb"), mock.patch.object(
            L, "_get_component_record", return_value=None
        ):
            for name, call in _guarded_calls(L):
                with self.subTest(handler=name):
                    try:
                        resp = call(HUMAN_CLAIMS)
                    except Exception:  # noqa: BLE001 - past the guard into mocked storage
                        continue
                    self.assertNotEqual(_body(resp).get("code"), "COMPONENT_DECIDER_REQUIRED")

    def test_assistant_key_keeps_transition_type_allowance_only(self):
        L = coordination_lambda
        event = {"body": json.dumps({"transition_type": "code"}), "headers": {"x-checkout-assistant-key": "assistant-key"}}
        with mock.patch.object(L, "_get_ddb"):
            resp = L._handle_components_update("comp-x", event, INTERNAL_KEY)
        self.assertNotEqual(_body(resp).get("code"), "COMPONENT_DECIDER_REQUIRED")
        event = {"body": json.dumps({"transition_type": "code", "status": "active"}),
                 "headers": {"x-checkout-assistant-key": "assistant-key"}}
        resp = L._handle_components_update("comp-x", event, INTERNAL_KEY)
        self.assertEqual(resp["statusCode"], 403)
        self.assertEqual(_body(resp).get("code"), "COMPONENT_DECIDER_REQUIRED")

    def test_agent_advance_path_is_unchanged_for_internal_key(self):
        """The agent evidence-gate path stays: internal-key is not refused by the decider guard on advance."""
        L = coordination_lambda
        self.assertFalse(L._require_component_decider(INTERNAL_KEY) is None)  # not a decider
        # is_io is the only line that changed; agents still reach the authority matrix.
        src = open(os.path.join(os.path.dirname(__file__), "lambda_function.py")).read()
        self.assertIn("is_io = _require_component_decider(claims) is None", src)


if __name__ == "__main__":
    unittest.main()
