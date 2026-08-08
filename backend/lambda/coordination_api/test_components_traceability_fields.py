"""ENC-TSK-N86 — PATCH /components/{id} must accept the traceability fields.

DVP-TSK-621 (B1-R4) sat blocked because the I1-I5 invariants of
DOC-157A790F9E8B section 2.2 are properties of maps instantiated FROM the
registry row. With ``component_repo_dir`` unset, the map
``c -> component_repo_dir(c)`` is not instantiated at all, so I2 is UNDEFINED
rather than satisfied, and I5's partition has no cell to attach to. The values
themselves were already derived and published in NX-2021-L/devops
``docs/component-traceability-DVP-TSK-699.md``; the only thing missing was a
write path.

The trap this file exists to pin: ``_handle_components_update`` iterates
``for field in updatable_fields``, so a field absent from that set is **silently
ignored** — the PATCH returns 200 and writes nothing. A test asserting only
"returns 200" would therefore pass against a completely broken handler. Every
assertion here checks the generated UpdateExpression instead.

Related: DVP-TSK-621, DVP-TSK-650, DVP-TSK-699, DOC-9FEB417260C8.
"""

from __future__ import annotations

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


INTERNAL_CLAIMS = {"auth_mode": "internal-key", "sub": "agent"}

TRACEABILITY_FIELDS = (
    "component_repo",
    "component_repo_dir",
    "component_repo_branch",
    "component_deploy_workflow",
    "component_deploy_target",
    "component_address",
    "lifecycle_status",
)


def _event(body: dict, *, method: str = "PATCH") -> dict:
    return {"httpMethod": method, "body": json.dumps(body)}


def _ddb():
    fake = mock.MagicMock()
    fake.exceptions.ConditionalCheckFailedException = type(
        "_FakeCCFE", (Exception,), {}
    )
    fake.update_item.return_value = {"Attributes": {}}
    return fake


class TraceabilityFieldsAreWritableTests(unittest.TestCase):
    def test_each_traceability_field_reaches_the_update_expression(self):
        """The whole point: present in updatable_fields, not silently dropped."""
        for field in TRACEABILITY_FIELDS:
            with self.subTest(field=field):
                fake = _ddb()
                with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
                    resp = coordination_lambda._handle_components_update(
                        "comp-devops-trino",
                        _event({field: "sentinel-value"}),
                        INTERNAL_CLAIMS,
                    )
                self.assertEqual(resp["statusCode"], 200)
                self.assertTrue(
                    fake.update_item.called,
                    f"{field} never reached update_item — silently dropped",
                )
                kwargs = fake.update_item.call_args.kwargs
                self.assertIn(
                    field,
                    kwargs["ExpressionAttributeNames"].values(),
                    f"{field} missing from ExpressionAttributeNames",
                )
                self.assertIn(
                    "sentinel-value",
                    [
                        list(v.values())[0]
                        for v in kwargs["ExpressionAttributeValues"].values()
                    ],
                    f"{field}'s value never made it into the write",
                )

    def test_an_unknown_field_is_still_ignored(self):
        """Guards the negative: widening the allowlist must not open it up.

        ``not_a_real_field`` should be dropped, so the only thing written is the
        updated_at bookkeeping the handler always adds.
        """
        fake = _ddb()
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_update(
                "comp-devops-trino",
                _event({"not_a_real_field": "x"}),
                INTERNAL_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 200)
        names = fake.update_item.call_args.kwargs["ExpressionAttributeNames"].values()
        self.assertNotIn("not_a_real_field", names)


class TransitionTypeGateIsUnchangedTests(unittest.TestCase):
    """The traceability widening must not weaken the one field that IS gated.

    ``transition_type`` drives checkout strictness (ENC-FTR-041), which is why
    it requires Cognito or the assistant key. The new fields are traceability
    metadata and deliberately do not carry that gate — but this asserts the
    gate itself still fires, so the widening cannot be mistaken for a general
    relaxation of component auth.
    """

    def test_internal_key_still_cannot_set_transition_type(self):
        resp = coordination_lambda._handle_components_update(
            "comp-devops-trino",
            _event({"transition_type": "no_code"}),
            INTERNAL_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 403)
        self.assertIn(
            "Cognito", json.loads(resp["body"])["error_envelope"]["message"]
        )

    def test_traceability_field_alongside_transition_type_is_still_refused(self):
        """A traceability field must not become a smuggling vector."""
        resp = coordination_lambda._handle_components_update(
            "comp-devops-trino",
            _event(
                {"component_repo_dir": "analytics/analytics-dashboard",
                 "transition_type": "no_code"}
            ),
            INTERNAL_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 403)


if __name__ == "__main__":
    unittest.main()
