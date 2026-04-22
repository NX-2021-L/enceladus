"""Tests for coordination_api component edge handlers (ENC-TSK-F46 AC[1]).

Covers:
- DESIGNS/IMPLEMENTS strict 1:1 cardinality:
  * 2 components refused the same task (task already has a DESIGNED_BY edge)
  * 2 tasks refused the same component (component already has a DESIGNS edge)
- DEPLOYS append-ok cardinality (allowed even when existing edges exist)
- 423 Locked on mutation after immutability threshold:
  * DESIGNS: locked when task closed_count >= 1
  * IMPLEMENTS: locked when task checkout_count >= 1
  * DEPLOYS: locked when linked task reached deploy-success status
- 409 on duplicate DESIGNS/IMPLEMENTS edge add
- Unknown edge_type validation
- Missing task / missing component rejection
- Component lifecycle_status PERMITTED gate for edge write
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


def _event(body):
    return {"httpMethod": "POST", "body": json.dumps(body or {})}


class _TCE(Exception):
    """Stand-in for ddb.exceptions.ConditionalCheckFailedException."""


class _TXE(Exception):
    """Stand-in for ddb.exceptions.TransactionCanceledException."""


def _approved_component(component_id="comp-x"):
    return {
        "component_id": component_id,
        "lifecycle_status": "approved",
        "project_id": "enceladus",
    }


def _open_task(task_id="ENC-TSK-X01"):
    return {"item_id": task_id, "status": "open"}


def _fake_transact_ddb():
    fake = mock.MagicMock()
    fake.exceptions.TransactionCanceledException = _TXE
    fake.transact_write_items.return_value = {}
    return fake


class ComponentAddEdgeCardinalityTests(unittest.TestCase):
    """Strict 1:1 cardinality enforcement for DESIGNS and IMPLEMENTS edges."""

    def setUp(self):
        coordination_lambda._COMPONENT_TRANSITION_TABLE_CACHE = None
        self._flag = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    # -------------------------------- basic guards

    def test_feature_flag_off_returns_503(self):
        with mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", False
        ):
            resp = coordination_lambda._handle_components_add_edge(
                "comp-x",
                _event({"edge_type": "DESIGNS", "task_id": "ENC-TSK-X01"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 503)

    def test_unknown_edge_type_returns_400(self):
        resp = coordination_lambda._handle_components_add_edge(
            "comp-x",
            _event({"edge_type": "REPLACES", "task_id": "ENC-TSK-X01"}),
            AGENT_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_missing_task_id_returns_400(self):
        resp = coordination_lambda._handle_components_add_edge(
            "comp-x",
            _event({"edge_type": "DESIGNS"}),
            AGENT_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_component_in_proposed_status_rejected(self):
        """lifecycle_status=proposed is BLOCKED — edges may only attach to PERMITTED statuses."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "proposed"},
        ):
            resp = coordination_lambda._handle_components_add_edge(
                "comp-x",
                _event({"edge_type": "DESIGNS", "task_id": "ENC-TSK-X01"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "EDGE_TARGET_BLOCKED")

    # -------------------------------- DESIGNS 1:1: component-side uniqueness

    def test_designs_edge_component_already_has_one_returns_409(self):
        """DESIGNS is strict 1:1 — 409 when component already has a DESIGNS edge."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value=_approved_component("comp-first"),
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value=_open_task("ENC-TSK-X02"),
        ), mock.patch.object(
            coordination_lambda,
            "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-OTHER"}],
        ):
            resp = coordination_lambda._handle_components_add_edge(
                "comp-first",
                _event({"edge_type": "DESIGNS", "task_id": "ENC-TSK-X02"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 409)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "EDGE_UNIQUENESS_VIOLATION")
        self.assertEqual(body["existing_task_id"], "ENC-TSK-OTHER")

    def test_designs_edge_second_component_also_refused_when_has_edge(self):
        """A different component that already has its own DESIGNS edge is also refused."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value=_approved_component("comp-second"),
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value=_open_task("ENC-TSK-X03"),
        ), mock.patch.object(
            coordination_lambda,
            "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-PRIOR"}],
        ):
            resp = coordination_lambda._handle_components_add_edge(
                "comp-second",
                _event({"edge_type": "DESIGNS", "task_id": "ENC-TSK-X03"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 409)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "EDGE_UNIQUENESS_VIOLATION")

    # -------------------------------- DESIGNS 1:1: task-side uniqueness

    def test_designs_edge_task_already_has_one_returns_409(self):
        """Task-side uniqueness: task already DESIGNED_BY another component."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value=_approved_component("comp-x"),
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value=_open_task("ENC-TSK-X02"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges", return_value=[]
        ), mock.patch.object(
            coordination_lambda,
            "_query_task_inverse_edges",
            return_value=[{"target_id": "comp-other"}],
        ):
            resp = coordination_lambda._handle_components_add_edge(
                "comp-x",
                _event({"edge_type": "DESIGNS", "task_id": "ENC-TSK-X02"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 409)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "EDGE_UNIQUENESS_VIOLATION")

    def test_designs_edge_second_task_also_refused_when_has_designer(self):
        """Task-side 1:1: a second task that already has DESIGNED_BY is refused too."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value=_approved_component("comp-y"),
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value=_open_task("ENC-TSK-Y01"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges", return_value=[]
        ), mock.patch.object(
            coordination_lambda,
            "_query_task_inverse_edges",
            return_value=[{"target_id": "comp-existing-designer"}],
        ):
            resp = coordination_lambda._handle_components_add_edge(
                "comp-y",
                _event({"edge_type": "DESIGNS", "task_id": "ENC-TSK-Y01"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 409)

    # -------------------------------- IMPLEMENTS 1:1 cardinality

    def test_implements_edge_component_already_has_one_returns_409(self):
        """IMPLEMENTS is strict 1:1 — 409 when component already has an IMPLEMENTS edge."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value=_approved_component("comp-impl"),
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value=_open_task("ENC-TSK-NEW"),
        ), mock.patch.object(
            coordination_lambda,
            "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-PRIOR"}],
        ):
            resp = coordination_lambda._handle_components_add_edge(
                "comp-impl",
                _event({"edge_type": "IMPLEMENTS", "task_id": "ENC-TSK-NEW"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 409)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "EDGE_UNIQUENESS_VIOLATION")

    def test_implements_edge_task_already_has_one_returns_409(self):
        """Task-side uniqueness for IMPLEMENTS: task already IMPLEMENTED_BY another component."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value=_approved_component("comp-x"),
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value=_open_task("ENC-TSK-IMPL"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges", return_value=[]
        ), mock.patch.object(
            coordination_lambda,
            "_query_task_inverse_edges",
            return_value=[{"target_id": "comp-other-impl"}],
        ):
            resp = coordination_lambda._handle_components_add_edge(
                "comp-x",
                _event({"edge_type": "IMPLEMENTS", "task_id": "ENC-TSK-IMPL"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 409)

    # -------------------------------- DESIGNS happy path writes forward+inverse

    def test_designs_edge_happy_path_writes_forward_and_inverse(self):
        """DESIGNS edge write: both forward and inverse rows created atomically."""
        fake = _fake_transact_ddb()
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value=_approved_component("comp-x"),
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value=_open_task("ENC-TSK-X02"),
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges", return_value=[]
        ), mock.patch.object(
            coordination_lambda, "_query_task_inverse_edges", return_value=[]
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=fake
        ):
            resp = coordination_lambda._handle_components_add_edge(
                "comp-x",
                _event({"edge_type": "DESIGNS", "task_id": "ENC-TSK-X02"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 201)
        body = json.loads(resp["body"])
        self.assertEqual(body["edge_type"], "DESIGNS")
        self.assertEqual(body["forward_edge_id"], "rel#comp-x#designs#ENC-TSK-X02")
        self.assertEqual(
            body["inverse_edge_id"], "rel#ENC-TSK-X02#designed-by#comp-x"
        )
        call = fake.transact_write_items.call_args
        self.assertEqual(len(call.kwargs["TransactItems"]), 2)

    # -------------------------------- DEPLOYS append-ok

    def test_deploys_edge_append_ok_even_with_existing(self):
        """DEPLOYS is append-ok: uniqueness check NOT performed, write proceeds."""
        fake = _fake_transact_ddb()
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={
                "component_id": "comp-x", "lifecycle_status": "development",
                "project_id": "enceladus",
            },
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value=_open_task("ENC-TSK-X03"),
        ), mock.patch.object(
            coordination_lambda,
            "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-PRIOR-DEPLOY"}],  # ignored
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=fake
        ):
            resp = coordination_lambda._handle_components_add_edge(
                "comp-x",
                _event({"edge_type": "DEPLOYS", "task_id": "ENC-TSK-X03"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 201)
        body = json.loads(resp["body"])
        self.assertEqual(body["cardinality"], "append_ok")

    def test_deploys_edge_third_add_also_succeeds(self):
        """DEPLOYS append-ok: adding a third DEPLOYS edge to the same component succeeds."""
        fake = _fake_transact_ddb()
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={
                "component_id": "comp-x", "lifecycle_status": "production",
                "project_id": "enceladus",
            },
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value=_open_task("ENC-TSK-X04"),
        ), mock.patch.object(
            coordination_lambda,
            "_query_component_edges",
            return_value=[
                {"target_id": "ENC-TSK-DEPLOY-1"},
                {"target_id": "ENC-TSK-DEPLOY-2"},
            ],
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=fake
        ):
            resp = coordination_lambda._handle_components_add_edge(
                "comp-x",
                _event({"edge_type": "DEPLOYS", "task_id": "ENC-TSK-X04"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 201)


class ComponentRemoveEdgeLockTests(unittest.TestCase):
    """423 Locked on edge removal attempts after immutability threshold is crossed."""

    def setUp(self):
        coordination_lambda._COMPONENT_TRANSITION_TABLE_CACHE = None
        self._flag = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def test_designs_edge_locked_when_closed_count_ge_1(self):
        """DESIGNS locks when linked task closed_count >= 1 (§4.1)."""
        with mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={"item_id": "ENC-TSK-X01", "closed_count": 1},
        ):
            resp = coordination_lambda._handle_components_remove_edge(
                "comp-x",
                _event({"edge_type": "DESIGNS", "task_id": "ENC-TSK-X01"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 423)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "EDGE_LOCKED")
        self.assertEqual(body["lock_trigger"], "closed_count_ge_1")

    def test_designs_edge_locked_at_closed_count_3(self):
        """DESIGNS remains locked at closed_count=3 (threshold is >=1)."""
        with mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={"item_id": "ENC-TSK-X01", "closed_count": 3},
        ):
            resp = coordination_lambda._handle_components_remove_edge(
                "comp-x",
                _event({"edge_type": "DESIGNS", "task_id": "ENC-TSK-X01"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 423)

    def test_implements_edge_locked_when_checkout_count_ge_1(self):
        """IMPLEMENTS locks when linked task checkout_count >= 1 (§4.2)."""
        with mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={"item_id": "ENC-TSK-X02", "checkout_count": 3},
        ):
            resp = coordination_lambda._handle_components_remove_edge(
                "comp-x",
                _event({"edge_type": "IMPLEMENTS", "task_id": "ENC-TSK-X02"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 423)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "EDGE_LOCKED")
        self.assertEqual(body["lock_trigger"], "checkout_count_ge_1")

    def test_implements_edge_locked_at_checkout_count_1(self):
        """IMPLEMENTS locks immediately at checkout_count=1."""
        with mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={"item_id": "ENC-TSK-X02", "checkout_count": 1},
        ):
            resp = coordination_lambda._handle_components_remove_edge(
                "comp-x",
                _event({"edge_type": "IMPLEMENTS", "task_id": "ENC-TSK-X02"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 423)

    def test_deploys_edge_locked_when_task_reached_deploy_success(self):
        """DEPLOYS per-edge lock: task status=deploy-success prevents removal (§4.3)."""
        with mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={"item_id": "ENC-TSK-X03", "status": "deploy-success"},
        ):
            resp = coordination_lambda._handle_components_remove_edge(
                "comp-x",
                _event({"edge_type": "DEPLOYS", "task_id": "ENC-TSK-X03"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 423)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "EDGE_LOCKED")
        self.assertEqual(body["lock_trigger"], "task_status_deploy_success")

    def test_unlocked_designs_edge_removed_atomically(self):
        """DESIGNS task closed_count=0 -> unlocked; transact_write_items fires for both rows."""
        fake = mock.MagicMock()
        fake.exceptions.TransactionCanceledException = _TXE
        fake.transact_write_items.return_value = {}
        with mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={
                "item_id": "ENC-TSK-X01", "closed_count": 0,
                "project_id": "enceladus",
            },
        ), mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={
                "component_id": "comp-x", "project_id": "enceladus",
            },
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=fake
        ):
            resp = coordination_lambda._handle_components_remove_edge(
                "comp-x",
                _event({"edge_type": "DESIGNS", "task_id": "ENC-TSK-X01"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["removed"])
        call = fake.transact_write_items.call_args
        self.assertEqual(len(call.kwargs["TransactItems"]), 2)


if __name__ == "__main__":
    unittest.main()
