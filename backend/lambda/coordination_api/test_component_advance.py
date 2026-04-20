"""Tests for coordination_api._handle_components_advance (ENC-TSK-F40 AC[1g]).

Exercises:
- Authority matrix (agent-permitted targets only).
- Evidence gate evaluation (DESIGNS/IMPLEMENTS counter thresholds + deploy-success).
- Happy path with DDB UpdateItem invocation.
- Hard-block (archived source, deprecated->development) rejection.
- Feature flag gate.
- io bypass of gates.
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


AGENT_CLAIMS = {"auth_mode": "internal-key", "sub": "agent-session"}
IO_CLAIMS = {
    "auth_mode": "cognito",
    "sub": "user-sub",
    "email": "io@example.com",
}


def _event(body):
    return {"httpMethod": "POST", "body": json.dumps(body or {})}


class _TCE(Exception):
    """Stand-in for ddb.exceptions.ConditionalCheckFailedException."""


def _fake_ddb_update_success(attrs):
    fake = mock.MagicMock()
    fake.exceptions.ConditionalCheckFailedException = _TCE
    fake.update_item.return_value = {"Attributes": attrs}
    return fake


class ComponentAdvanceTests(unittest.TestCase):

    def setUp(self):
        coordination_lambda._COMPONENT_TRANSITION_TABLE_CACHE = None
        self._flag = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def test_feature_flag_off_returns_503(self):
        with mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", False
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "designed"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 503)

    def test_missing_target_status_returns_400(self):
        resp = coordination_lambda._handle_components_advance(
            "comp-x", _event({}), AGENT_CLAIMS
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_unknown_component_returns_404(self):
        with mock.patch.object(
            coordination_lambda, "_get_component_record", return_value=None
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-missing", _event({"target_status": "designed"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 404)

    def test_archived_source_returns_404_opacity(self):
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "archived"},
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "production"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 404)

    def test_deprecated_to_development_hard_block(self):
        """Hard block per §3.2 / DD-3."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "deprecated"},
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "development"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "LIFECYCLE_TRANSITION_UNMET")

    def test_agent_denied_for_io_only_target(self):
        """Agents may not target 'approved' etc. — only §3.3 agent-permitted set."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "designed"},
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "approved"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 403)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "AUTHORITY_MATRIX_DENIED")

    def test_approved_to_designed_gate_missing_edge(self):
        """Agent advance approved->designed requires a DESIGNS edge; with
        no edge registered, expect GATE_CONDITION_UNMET."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "approved"},
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges", return_value=[]
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "designed"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "GATE_CONDITION_UNMET")
        self.assertEqual(body["required_edge"], "DESIGNS")
        self.assertTrue(body.get("missing_edge"))

    def test_approved_to_designed_gate_task_not_closed(self):
        """DESIGNS edge exists but task closed_count=0 -> GATE_CONDITION_UNMET."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "approved"},
        ), mock.patch.object(
            coordination_lambda,
            "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X01", "relationship_type": "designs"}],
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={"item_id": "ENC-TSK-X01", "closed_count": 0},
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "designed"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "GATE_CONDITION_UNMET")
        self.assertEqual(body["observed_value"], 0)

    def test_approved_to_designed_gate_passes(self):
        """DESIGNS edge with closed_count=1 passes; DDB update fires."""
        fake = _fake_ddb_update_success({
            "component_id": {"S": "comp-x"},
            "lifecycle_status": {"S": "designed"},
        })
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "approved"},
        ), mock.patch.object(
            coordination_lambda,
            "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X01", "relationship_type": "designs"}],
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={"item_id": "ENC-TSK-X01", "closed_count": 1},
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=fake
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "designed"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "designed")
        self.assertEqual(body["previous_lifecycle_status"], "approved")
        self.assertEqual(body["advanced_by"], "agent")

    def test_designed_to_development_gate_fails_checkout_count_zero(self):
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "designed"},
        ), mock.patch.object(
            coordination_lambda,
            "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X02", "relationship_type": "implements"}],
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={"item_id": "ENC-TSK-X02", "checkout_count": 0},
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "development"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "GATE_CONDITION_UNMET")
        self.assertEqual(body["required_edge"], "IMPLEMENTS")

    def test_development_to_production_requires_deploy_success(self):
        """Task must have status=deploy-success to gate development->production."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "development"},
        ), mock.patch.object(
            coordination_lambda,
            "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X02"}],
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={"item_id": "ENC-TSK-X02", "status": "merged-main"},
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "production"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "GATE_CONDITION_UNMET")
        self.assertEqual(body["observed_task_status"], "merged-main")

    def test_production_to_code_red_no_gate(self):
        fake = _fake_ddb_update_success({
            "component_id": {"S": "comp-x"},
            "lifecycle_status": {"S": "code-red"},
        })
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "production"},
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=fake
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "code-red"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "code-red")

    def test_io_bypasses_agent_target_restrictions(self):
        """io may target any table-permitted status (even ones outside the
        agent-permitted set) without triggering AUTHORITY_MATRIX_DENIED.
        Here: designed->approved (backstep) is io-only."""
        fake = _fake_ddb_update_success({
            "component_id": {"S": "comp-x"},
            "lifecycle_status": {"S": "approved"},
        })
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "designed"},
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=fake
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "approved"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["advanced_by"], "io")

    def test_io_bypasses_evidence_gates(self):
        """io may advance approved->designed without a DESIGNS edge (no gate)."""
        fake = _fake_ddb_update_success({
            "component_id": {"S": "comp-x"},
            "lifecycle_status": {"S": "designed"},
        })
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "approved"},
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges", return_value=[]
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=fake
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "designed"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["advanced_by"], "io")


if __name__ == "__main__":
    unittest.main()
