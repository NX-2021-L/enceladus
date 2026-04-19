"""F50/AC-8 — coordination_api required_transition_type create/update tests.

Covers the four assertions required by ENC-TSK-F50 AC-8:

    (a) POST /components without required_transition_type returns 400 (Option A
        — strict rejection, documented in governance_data_dictionary.json
        :: checkout_service.required_transition_type_enforcement).
    (b) POST /components with an invalid enum value returns 400.
    (c) PATCH /components/{id} that attempts to unset required_transition_type
        to null/empty returns 400.
    (d) PATCH /components/{id} with a valid enum value and proper auth
        succeeds (200).

Related: ENC-TSK-F50, ENC-ISS-270, DOC-240A67973B13.
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


COGNITO_CLAIMS = {
    "auth_mode": "cognito",
    "sub": "user-sub-123",
    "email": "lead@example.com",
    "cognito:username": "lead",
}
INTERNAL_CLAIMS = {"auth_mode": "internal-key", "sub": "agent"}


def _event(body: dict | None, *, method: str = "POST") -> dict:
    return {"httpMethod": method, "body": json.dumps(body or {})}


def _happy_path_ddb(return_attrs: dict | None = None):
    """Build a MagicMock ddb whose put_item and update_item both succeed."""
    fake = mock.MagicMock()
    # Distinct exception class so the handler's ``except ddb.exceptions.…``
    # branches don't accidentally match success paths.
    fake.exceptions.ConditionalCheckFailedException = type(
        "_FakeCCFE", (Exception,), {}
    )
    fake.put_item.return_value = {}
    fake.update_item.return_value = {
        "Attributes": return_attrs or {"component_id": {"S": "comp-x"}}
    }
    return fake


class CreateRequiredTransitionTypeTests(unittest.TestCase):
    """AC-8(a), (b) and the create happy-path coverage."""

    _base_body = {
        "component_name": "Test Component",
        "project_id": "enceladus",
        "category": "lambda",
    }

    def test_create_without_required_transition_type_returns_400(self):
        """AC-8(a): absent field returns 400 with field=required_transition_type."""
        resp = coordination_lambda._handle_components_create(
            _event(dict(self._base_body)),
            INTERNAL_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        details = body["error_envelope"]["details"]
        self.assertEqual(details["field"], "required_transition_type")
        self.assertIn("github_pr_deploy", details["allowed_values"])
        self.assertIn("no_code", details["allowed_values"])
        # Self-correcting envelope must surface the governance rule.
        self.assertIn("required_transition_type", body["error_envelope"]["message"])
        self.assertIn("ENC-TSK-F50", body["error_envelope"]["message"])

    def test_create_with_invalid_required_transition_type_enum_returns_400(self):
        """AC-8(b): invalid enum value returns 400."""
        body = dict(self._base_body)
        body["required_transition_type"] = "definitely-not-a-real-type"
        resp = coordination_lambda._handle_components_create(
            _event(body),
            INTERNAL_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 400)
        envelope = json.loads(resp["body"])["error_envelope"]
        self.assertIn(
            "Invalid required_transition_type", envelope["message"]
        )
        self.assertEqual(envelope["details"]["field"], "required_transition_type")

    def test_create_with_valid_required_transition_type_persists_field(self):
        """Create happy path stamps both transition_type and required_transition_type."""
        body = dict(self._base_body)
        body["required_transition_type"] = "github_pr_deploy"
        fake = _happy_path_ddb()
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_create(
                _event(body),
                INTERNAL_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 201)
        # The item passed to put_item should carry required_transition_type.
        fake.put_item.assert_called_once()
        put_kwargs = fake.put_item.call_args.kwargs
        item_ddb = put_kwargs["Item"]
        # DynamoDB value is wrapped as {"S": "<value>"}; tolerant extraction.
        required_ddb = item_ddb.get("required_transition_type")
        self.assertIsNotNone(required_ddb, "required_transition_type not persisted")
        self.assertEqual(required_ddb.get("S"), "github_pr_deploy")

    def test_create_with_whitespace_only_required_transition_type_returns_400(self):
        """Whitespace-only value should be treated as absent."""
        body = dict(self._base_body)
        body["required_transition_type"] = "   "
        resp = coordination_lambda._handle_components_create(
            _event(body),
            INTERNAL_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(
            json.loads(resp["body"])["error_envelope"]["details"]["field"],
            "required_transition_type",
        )


class PatchRequiredTransitionTypeTests(unittest.TestCase):
    """AC-8(c), (d) for the PATCH surface."""

    def test_patch_unset_required_transition_type_to_null_returns_400(self):
        """AC-8(c): explicit null returns 400."""
        resp = coordination_lambda._handle_components_update(
            "comp-checkout-service",
            _event({"required_transition_type": None}, method="PATCH"),
            COGNITO_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 400)
        envelope = json.loads(resp["body"])["error_envelope"]
        self.assertIn("cannot be unset", envelope["message"])
        self.assertEqual(envelope["details"]["field"], "required_transition_type")

    def test_patch_unset_required_transition_type_to_empty_string_returns_400(self):
        """AC-8(c) variant: empty string is treated as unset."""
        resp = coordination_lambda._handle_components_update(
            "comp-checkout-service",
            _event({"required_transition_type": ""}, method="PATCH"),
            COGNITO_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 400)
        details = json.loads(resp["body"])["error_envelope"]["details"]
        self.assertEqual(details["field"], "required_transition_type")

    def test_patch_unset_required_transition_type_to_whitespace_returns_400(self):
        resp = coordination_lambda._handle_components_update(
            "comp-checkout-service",
            _event({"required_transition_type": "   "}, method="PATCH"),
            COGNITO_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_patch_invalid_enum_returns_400(self):
        resp = coordination_lambda._handle_components_update(
            "comp-checkout-service",
            _event(
                {"required_transition_type": "made-up-type"}, method="PATCH"
            ),
            COGNITO_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 400)
        self.assertIn(
            "Invalid required_transition_type",
            json.loads(resp["body"])["error_envelope"]["message"],
        )

    def test_patch_internal_key_without_cognito_returns_403(self):
        """Direct agent writes with internal key are not permitted."""
        resp = coordination_lambda._handle_components_update(
            "comp-checkout-service",
            _event({"required_transition_type": "no_code"}, method="PATCH"),
            INTERNAL_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 403)

    def test_patch_valid_required_transition_type_update_succeeds(self):
        """AC-8(d): valid value + Cognito auth returns 200."""
        fake = _happy_path_ddb(
            return_attrs={
                "component_id": {"S": "comp-checkout-service"},
                "required_transition_type": {"S": "no_code"},
            }
        )
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_update(
                "comp-checkout-service",
                _event({"required_transition_type": "no_code"}, method="PATCH"),
                COGNITO_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 200)
        # Verify update_item was called and the expression includes the field.
        fake.update_item.assert_called_once()
        call_kwargs = fake.update_item.call_args.kwargs
        # Either the update expression names required_transition_type directly,
        # or the attr_names map carries it under a safe alias. Both are acceptable.
        update_expr = call_kwargs.get("UpdateExpression", "")
        attr_names = call_kwargs.get("ExpressionAttributeNames", {})
        mentioned = (
            "required_transition_type" in update_expr
            or "required_transition_type" in attr_names.values()
        )
        self.assertTrue(
            mentioned,
            "update_item did not write the required_transition_type field",
        )


if __name__ == "__main__":
    unittest.main()
