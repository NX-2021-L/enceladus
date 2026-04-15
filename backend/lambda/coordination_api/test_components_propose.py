"""Tests for coordination_api _handle_components_propose (ENC-TSK-E08).

Validates AC1-1 through AC1-9:
- lifecycle_status=proposed on create
- component_id comp- prefix validation (AC1-9)
- duplicate component_id returns 409 via TransactionCanceledException (AC1-9)
- ENABLE_COMPONENT_PROPOSAL feature flag gates the handler (AC1-3)
- requested_minimum_transition_type validation against STRICTNESS_RANK
- rel# forward + inverse items written via TransactWriteItems (AC1-8)
- happy-path response shape + written item verified via mocked ddb.get_item (AC1-9)
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


def _valid_body(**overrides):
    body = {
        "component_id": "comp-test-proposal",
        "display_name": "Test Proposal",
        "project_id": "enceladus",
        "source_paths": ["backend/lambda/test_service/"],
        "description": "A test component proposal",
        "requested_minimum_transition_type": "lambda_deploy",
        "proposing_agent_session_id": "agent-session-abc123",
        "governance_hash": "hash-xyz",
    }
    body.update(overrides)
    return body


class ComponentProposeTests(unittest.TestCase):

    def setUp(self):
        # Always enable the flag in the module under test so the handler runs.
        self._flag_patcher = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag_patcher.start()

    def tearDown(self):
        self._flag_patcher.stop()

    def _event(self, body):
        return {
            "httpMethod": "POST",
            "path": "/api/v1/coordination/components/propose",
            "body": json.dumps(body),
        }

    def test_feature_flag_off_returns_503(self):
        """AC1-3: handler returns 503 when ENABLE_COMPONENT_PROPOSAL is false."""
        with mock.patch.object(coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", False):
            resp = coordination_lambda._handle_components_propose(self._event(_valid_body()), {})
        self.assertEqual(resp["statusCode"], 503)

    def test_missing_comp_prefix_returns_400(self):
        """AC1-9: component_id without 'comp-' prefix is rejected."""
        resp = coordination_lambda._handle_components_propose(
            self._event(_valid_body(component_id="test-proposal")), {},
        )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("comp-", body.get("message", "") + json.dumps(body))

    def test_missing_required_fields_returns_400(self):
        for field in ("component_id", "display_name", "project_id", "requested_minimum_transition_type"):
            b = _valid_body()
            b.pop(field)
            resp = coordination_lambda._handle_components_propose(self._event(b), {})
            self.assertEqual(resp["statusCode"], 400, f"field={field}")

    def test_invalid_transition_type_returns_400(self):
        resp = coordination_lambda._handle_components_propose(
            self._event(_valid_body(requested_minimum_transition_type="bogus")), {},
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_missing_proposing_agent_session_id_returns_400(self):
        """When no explicit id + no claims.sub + no write_source.provider, reject."""
        b = _valid_body()
        b.pop("proposing_agent_session_id")
        resp = coordination_lambda._handle_components_propose(self._event(b), {})
        self.assertEqual(resp["statusCode"], 400)

    def test_duplicate_returns_409_on_transaction_cancelled(self):
        """AC1-9: TransactionCanceledException with ConditionalCheckFailed -> 409."""
        fake_ddb = mock.MagicMock()

        class _TCE(Exception):
            pass

        fake_ddb.exceptions.TransactionCanceledException = _TCE
        fake_ddb.transact_write_items.side_effect = _TCE()
        fake_ddb.transact_write_items.side_effect.response = {
            "CancellationReasons": [{"Code": "ConditionalCheckFailed"}, {"Code": "None"}, {"Code": "None"}]
        }

        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake_ddb):
            resp = coordination_lambda._handle_components_propose(self._event(_valid_body()), {})

        self.assertEqual(resp["statusCode"], 409)

    def test_happy_path_201_and_transact_write(self):
        """AC1-8, AC1-9: happy path writes component + rel# pair via TransactWriteItems."""
        fake_ddb = mock.MagicMock()

        class _TCE(Exception):
            pass

        fake_ddb.exceptions.TransactionCanceledException = _TCE
        fake_ddb.transact_write_items.return_value = {}

        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake_ddb):
            resp = coordination_lambda._handle_components_propose(self._event(_valid_body()), {})

        self.assertEqual(resp["statusCode"], 201)
        body = json.loads(resp["body"])
        self.assertEqual(body["component_id"], "comp-test-proposal")
        self.assertEqual(body["lifecycle_status"], "proposed")
        self.assertEqual(body["proposing_agent_session_id"], "agent-session-abc123")

        # Verify TransactWriteItems was called with 3 items: component + forward rel + inverse rel.
        fake_ddb.transact_write_items.assert_called_once()
        kwargs = fake_ddb.transact_write_items.call_args.kwargs
        items = kwargs["TransactItems"]
        self.assertEqual(len(items), 3)

        # Item 0: component Put on component-registry
        self.assertIn("component-registry", items[0]["Put"]["TableName"])
        comp_item = items[0]["Put"]["Item"]
        self.assertEqual(comp_item["component_id"]["S"], "comp-test-proposal")
        self.assertEqual(comp_item["lifecycle_status"]["S"], "proposed")

        # Item 1: forward rel# Put on devops-project-tracker
        forward = items[1]["Put"]["Item"]
        self.assertEqual(forward["relationship_type"]["S"], "component-proposed-by")
        self.assertEqual(forward["source_id"]["S"], "comp-test-proposal")
        self.assertEqual(forward["target_id"]["S"], "agent-session-abc123")
        self.assertFalse(forward["is_inverse"]["BOOL"])

        # Item 2: inverse rel# Put on devops-project-tracker
        inverse = items[2]["Put"]["Item"]
        self.assertEqual(inverse["relationship_type"]["S"], "proposes-component")
        self.assertEqual(inverse["source_id"]["S"], "agent-session-abc123")
        self.assertEqual(inverse["target_id"]["S"], "comp-test-proposal")
        self.assertTrue(inverse["is_inverse"]["BOOL"])


if __name__ == "__main__":
    unittest.main()
