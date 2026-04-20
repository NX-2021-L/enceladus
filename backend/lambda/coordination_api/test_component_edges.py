"""Tests for coordination_api component edge handlers (ENC-TSK-F40 AC[1b..1d]).

Exercises:
- DESIGNS/IMPLEMENTS strict 1:1 cardinality (409 at both endpoints).
- DEPLOYS append-ok cardinality.
- 423 Locked on immutable-edge mutation attempts.
- Unknown edge_type validation.
- Missing task / missing component rejection.
- Component lifecycle_status PERMITTED gate for edge write.
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


class ComponentAddEdgeTests(unittest.TestCase):

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

    def test_component_in_blocked_status_rejected(self):
        """lifecycle_status=proposed is BLOCKED — edges may only attach to
        components in PERMITTED_STATUSES."""
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

    def test_designs_edge_component_already_has_one_returns_409(self):
        """DESIGNS is strict 1:1 — 409 when the component already has an edge."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={
                "component_id": "comp-x", "lifecycle_status": "approved",
                "project_id": "enceladus",
            },
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={"item_id": "ENC-TSK-X02", "status": "open"},
        ), mock.patch.object(
            coordination_lambda,
            "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-OTHER"}],
        ):
            resp = coordination_lambda._handle_components_add_edge(
                "comp-x",
                _event({"edge_type": "DESIGNS", "task_id": "ENC-TSK-X02"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 409)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "EDGE_UNIQUENESS_VIOLATION")
        self.assertEqual(body["existing_task_id"], "ENC-TSK-OTHER")

    def test_designs_edge_task_already_has_one_returns_409(self):
        """Task-side uniqueness: task already DESIGNED_BY another component."""
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={
                "component_id": "comp-x", "lifecycle_status": "approved",
                "project_id": "enceladus",
            },
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={"item_id": "ENC-TSK-X02", "status": "open"},
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

    def test_designs_edge_happy_path_writes_forward_and_inverse(self):
        fake = mock.MagicMock()
        fake.exceptions.TransactionCanceledException = _TXE
        fake.transact_write_items.return_value = {}
        with mock.patch.object(
            coordination_lambda,
            "_get_component_record",
            return_value={
                "component_id": "comp-x", "lifecycle_status": "approved",
                "project_id": "enceladus",
            },
        ), mock.patch.object(
            coordination_lambda,
            "_get_task_record",
            return_value={"item_id": "ENC-TSK-X02", "status": "open"},
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
        # transact_write_items called with 2 Put items.
        call = fake.transact_write_items.call_args
        self.assertEqual(len(call.kwargs["TransactItems"]), 2)

    def test_deploys_edge_append_ok_even_with_existing(self):
        """DEPLOYS is append-ok: uniqueness check is NOT performed."""
        fake = mock.MagicMock()
        fake.exceptions.TransactionCanceledException = _TXE
        fake.transact_write_items.return_value = {}
        # The uniqueness-check mocks don't matter for DEPLOYS — we don't
        # call them. Sanity-check that the write path is reached anyway.
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
            return_value={"item_id": "ENC-TSK-X03", "status": "open"},
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


class ComponentRemoveEdgeTests(unittest.TestCase):

    def setUp(self):
        coordination_lambda._COMPONENT_TRANSITION_TABLE_CACHE = None
        self._flag = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def test_designs_edge_locked_by_closed_count_returns_423(self):
        """DESIGNS locks when linked task closed_count >= 1."""
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

    def test_implements_edge_locked_by_checkout_count_returns_423(self):
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

    def test_deploys_edge_locked_by_deploy_success_returns_423(self):
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

    def test_unlocked_edge_removed_atomically(self):
        """DESIGNS task closed_count=0 -> unlocked; transact_write_items fires."""
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
