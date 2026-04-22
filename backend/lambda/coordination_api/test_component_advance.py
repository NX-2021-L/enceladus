"""Tests for coordination_api._handle_components_advance (ENC-TSK-F46 AC[0]).

Covers all 15 transitions in the FTR-076 v2 state machine including:
- All valid table-permitted transitions (13 valid + 2 hard blocks = 15 total)
- Hard-block assertions: deprecated->development, archived->any
- Authority matrix (agent-permitted targets only)
- Evidence gate evaluation (DESIGNS/IMPLEMENTS counter thresholds + deploy-success)
- Happy path with DDB UpdateItem invocation
- Feature flag gate
- io bypass of gates

The 8 lifecycle statuses per DOC-546B896390EA §3.1:
  proposed, approved, designed, development, production, code-red, deprecated, archived

The 13 valid transitions per §3.2:
  proposed -> approved, proposed -> archived
  approved -> designed
  designed -> development, designed -> approved
  development -> production, development -> designed
  production -> code-red, production -> deprecated, production -> development
  code-red -> production, code-red -> deprecated
  deprecated -> production

Hard blocks (rejected even though both statuses are valid):
  deprecated -> development  (forbidden per §3.2 / DD-3: version-fork required)
  archived -> any            (archived has empty transition list)
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


def _component_at(status):
    return {"component_id": "comp-x", "lifecycle_status": status}


def _task_at(status, closed_count=0, checkout_count=0):
    return {
        "item_id": "ENC-TSK-X01",
        "status": status,
        "closed_count": closed_count,
        "checkout_count": checkout_count,
    }


def _fake_ddb(target_status):
    return _fake_ddb_update_success({
        "component_id": {"S": "comp-x"},
        "lifecycle_status": {"S": target_status},
    })


class ComponentAdvanceTests(unittest.TestCase):

    def setUp(self):
        coordination_lambda._COMPONENT_TRANSITION_TABLE_CACHE = None
        self._flag = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    # ------------------------------------------------------------------ guards

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

    def test_invalid_target_status_returns_400(self):
        resp = coordination_lambda._handle_components_advance(
            "comp-x", _event({"target_status": "nonexistent_status"}), AGENT_CLAIMS
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

    # ------------------------------------------- hard block: archived->any (opacity)

    def test_archived_source_to_production_returns_404_opacity(self):
        """Hard block: archived -> any. Opacity: indistinguishable from 404."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("archived"),
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "production"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 404)

    def test_archived_source_to_deprecated_returns_404_opacity(self):
        """Hard block: archived -> any even when io-callers try."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("archived"),
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "deprecated"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 404)

    def test_archived_source_to_code_red_returns_404_opacity(self):
        """Hard block: archived -> any, no valid targets for archived status."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("archived"),
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "code-red"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 404)

    # --------------------------------- hard block: deprecated->development

    def test_deprecated_to_development_hard_block_agent(self):
        """Hard block per §3.2 / DD-3: version-fork required for deprecated->development."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("deprecated"),
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "development"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "LIFECYCLE_TRANSITION_UNMET")

    def test_deprecated_to_development_hard_block_io(self):
        """Hard block also applies to io — Cognito auth does not bypass hard blocks."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("deprecated"),
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "development"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "LIFECYCLE_TRANSITION_UNMET")

    # ---------------------------------------- authority matrix (agent restricted)

    def test_agent_denied_for_approved_target(self):
        """Agents may not target 'approved' — io only per §3.3."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("designed"),
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "approved"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 403)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "AUTHORITY_MATRIX_DENIED")

    def test_agent_denied_for_deprecated_target(self):
        """Agents may not target 'deprecated' — io only."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("production"),
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "deprecated"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 403)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "AUTHORITY_MATRIX_DENIED")

    # ----------- transition 1: proposed -> approved (io only)

    def test_proposed_to_approved_io_path(self):
        """Transition 1/13: proposed -> approved (io path, table-permitted)."""
        fake = _fake_ddb("approved")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("proposed"),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "approved"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "approved")
        self.assertEqual(body["advanced_by"], "io")

    # ----------- transition 2: proposed -> archived (io only)

    def test_proposed_to_archived_io_path(self):
        """Transition 2/13: proposed -> archived (io path, table-permitted)."""
        fake = _fake_ddb("archived")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("proposed"),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "archived"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "archived")

    # ----------- transition 3: approved -> designed (agent, gate: DESIGNS + closed_count>=1)

    def test_approved_to_designed_gate_missing_edge(self):
        """Transition 3 gate: approved->designed requires a DESIGNS edge."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("approved"),
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
        """Transition 3 gate: DESIGNS edge exists but closed_count=0."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("approved"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X01", "relationship_type": "designs"}],
        ), mock.patch.object(
            coordination_lambda, "_get_task_record",
            return_value=_task_at("closed", closed_count=0),
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "designed"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "GATE_CONDITION_UNMET")
        self.assertEqual(body["observed_value"], 0)

    def test_approved_to_designed_gate_passes(self):
        """Transition 3/13 happy path: DESIGNS edge with closed_count=1 passes."""
        fake = _fake_ddb("designed")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("approved"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X01", "relationship_type": "designs"}],
        ), mock.patch.object(
            coordination_lambda, "_get_task_record",
            return_value=_task_at("closed", closed_count=1),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "designed"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "designed")
        self.assertEqual(body["previous_lifecycle_status"], "approved")
        self.assertEqual(body["advanced_by"], "agent")

    # ----------- transition 4: designed -> development (agent, gate: IMPLEMENTS + checkout_count>=1)

    def test_designed_to_development_gate_no_edge(self):
        """Transition 4 gate: designed->development requires IMPLEMENTS edge."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("designed"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges", return_value=[]
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "development"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "GATE_CONDITION_UNMET")
        self.assertEqual(body["required_edge"], "IMPLEMENTS")

    def test_designed_to_development_gate_checkout_count_zero(self):
        """Transition 4 gate: IMPLEMENTS edge but checkout_count=0 still fails."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("designed"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X02", "relationship_type": "implements"}],
        ), mock.patch.object(
            coordination_lambda, "_get_task_record",
            return_value=_task_at("in-progress", checkout_count=0),
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "development"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "GATE_CONDITION_UNMET")
        self.assertEqual(body["required_edge"], "IMPLEMENTS")

    def test_designed_to_development_gate_passes(self):
        """Transition 4/13 happy path: IMPLEMENTS edge with checkout_count=1."""
        fake = _fake_ddb("development")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("designed"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X02", "relationship_type": "implements"}],
        ), mock.patch.object(
            coordination_lambda, "_get_task_record",
            return_value=_task_at("in-progress", checkout_count=1),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "development"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "development")

    # ----------- transition 5: designed -> approved (io only, backstep)

    def test_designed_to_approved_io_path(self):
        """Transition 5/13: designed -> approved (io backstep, table-permitted)."""
        fake = _fake_ddb("approved")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("designed"),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "approved"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "approved")
        self.assertEqual(body["advanced_by"], "io")

    # ----------- transition 6: development -> production (agent, gate: IMPLEMENTS + deploy-success)

    def test_development_to_production_requires_deploy_success(self):
        """Transition 6 gate: IMPLEMENTS edge task must have status=deploy-success."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("development"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X02"}],
        ), mock.patch.object(
            coordination_lambda, "_get_task_record",
            return_value=_task_at("merged-main"),
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "production"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "GATE_CONDITION_UNMET")
        self.assertEqual(body["observed_task_status"], "merged-main")

    def test_development_to_production_passes_on_deploy_success(self):
        """Transition 6/13 happy path: IMPLEMENTS edge task=deploy-success."""
        fake = _fake_ddb("production")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("development"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X02"}],
        ), mock.patch.object(
            coordination_lambda, "_get_task_record",
            return_value=_task_at("deploy-success"),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "production"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "production")

    # ----------- transition 7: development -> designed (io only, regression)

    def test_development_to_designed_io_path(self):
        """Transition 7/13: development -> designed (io regression step)."""
        fake = _fake_ddb("designed")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("development"),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "designed"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "designed")
        self.assertEqual(body["advanced_by"], "io")

    # ----------- transition 8: production -> code-red (agent, no gate)

    def test_production_to_code_red_no_gate(self):
        """Transition 8/13: production -> code-red (agent-permitted, no evidence gate)."""
        fake = _fake_ddb("code-red")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("production"),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "code-red"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "code-red")

    # ----------- transition 9: production -> deprecated (io only)

    def test_production_to_deprecated_io_path(self):
        """Transition 9/13: production -> deprecated (io only)."""
        fake = _fake_ddb("deprecated")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("production"),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "deprecated"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "deprecated")

    # ----------- transition 10: production -> development (io only)

    def test_production_to_development_io_path(self):
        """Transition 10/13: production -> development (io regression)."""
        fake = _fake_ddb("development")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("production"),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "development"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "development")

    # ----------- transition 11: code-red -> production (agent, no gate)

    def test_code_red_to_production_no_gate(self):
        """Transition 11/13: code-red -> production (no evidence gate)."""
        fake = _fake_ddb("production")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("code-red"),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "production"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "production")

    # ----------- transition 12: code-red -> deprecated (io only)

    def test_code_red_to_deprecated_io_path(self):
        """Transition 12/13: code-red -> deprecated (io only)."""
        fake = _fake_ddb("deprecated")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("code-red"),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "deprecated"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "deprecated")

    # ----------- transition 13: deprecated -> production (io only)

    def test_deprecated_to_production_io_path(self):
        """Transition 13/13: deprecated -> production (io only)."""
        fake = _fake_ddb("production")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("deprecated"),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "production"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "production")

    # -------------------------------- io bypasses gates

    def test_io_bypasses_agent_target_restrictions(self):
        """io may target any table-permitted status including io-only ones (backstep)."""
        fake = _fake_ddb("approved")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("designed"),
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "approved"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["advanced_by"], "io")

    def test_io_bypasses_evidence_gates(self):
        """io may advance approved->designed without a DESIGNS edge (no gate applied)."""
        fake = _fake_ddb("designed")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("approved"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges", return_value=[]
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "designed"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["advanced_by"], "io")

    def test_io_bypasses_implements_gate(self):
        """io may advance designed->development without an IMPLEMENTS edge."""
        fake = _fake_ddb("development")
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("designed"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges", return_value=[]
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "development"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["advanced_by"], "io")

    # -------------------------------- non-permitted transitions (table-blocked)

    def test_proposed_to_development_not_table_permitted(self):
        """proposed -> development is not in the transition table — blocked."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("proposed"),
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "development"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "LIFECYCLE_TRANSITION_UNMET")

    def test_approved_to_production_not_table_permitted(self):
        """approved -> production is not in the transition table — blocked."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value=_component_at("approved"),
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "production"}), IO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)


if __name__ == "__main__":
    unittest.main()
