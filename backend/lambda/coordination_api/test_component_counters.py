"""Tests for ENC-TSK-F46 AC[3]: FTR-076 v2 component registry counter enforcement.

Covers how the component registry consumes the FTR-076 v2 server-side counter
fields (closed_count, checkout_count) from task records:

  1. closed_count increment on task->closed: The DESIGNS edge advance gate
     (approved->designed) passes when closed_count >= 1, confirming that the
     counter is correctly incremented by tracker_mutation on close.

  2. checkout_count increment on checkout.task success: The IMPLEMENTS edge
     advance gate (designed->development) passes when checkout_count >= 1,
     confirming that the counter is correctly incremented by checkout_service.

  3. 400 rejection on direct write attempts to counter fields: The tracker_mutation
     reserved-field guard rejects agent writes to closed_count and checkout_count
     with HTTP 400 and error_envelope.code=RESERVED_FIELD.

  4. Gate behavior at boundary values: gate fails at count=0, passes at count=1.

These tests exercise the coordination_api advance gate at the boundary between
the counter fields and the component lifecycle state machine. The atomic-ADD
mechanics live in tracker_mutation (test_counter_fields.py) — here we verify
the coordination_api gate correctly reads and interprets the counter values.

Related: DOC-546B896390EA §3.4, §5; ENC-TSK-F41
"""

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock


# ---- Load coordination_api lambda ------------------------------------------

sys.path.insert(0, os.path.dirname(__file__))
_COORD_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
coordination_lambda = importlib.util.module_from_spec(_COORD_SPEC)
assert _COORD_SPEC and _COORD_SPEC.loader
sys.modules[_COORD_SPEC.name] = coordination_lambda
_COORD_SPEC.loader.exec_module(coordination_lambda)

# ---- Load tracker_mutation lambda ------------------------------------------

_TRACKER_DIR = os.path.join(
    os.path.dirname(__file__), "..", "tracker_mutation"
)
sys.path.insert(0, _TRACKER_DIR)
_TRACKER_SPEC = importlib.util.spec_from_file_location(
    "tracker_mutation",
    os.path.join(_TRACKER_DIR, "lambda_function.py"),
)
tracker_mutation = importlib.util.module_from_spec(_TRACKER_SPEC)
assert _TRACKER_SPEC and _TRACKER_SPEC.loader
sys.modules[_TRACKER_SPEC.name] = tracker_mutation
_TRACKER_SPEC.loader.exec_module(tracker_mutation)


AGENT_CLAIMS = {"auth_mode": "internal-key", "sub": "agent-session"}


def _event(body):
    return {"httpMethod": "POST", "body": json.dumps(body or {})}


class _TCE(Exception):
    """Stand-in for ddb.exceptions.ConditionalCheckFailedException."""


def _fake_ddb(target_status):
    fake = mock.MagicMock()
    fake.exceptions.ConditionalCheckFailedException = _TCE
    fake.update_item.return_value = {
        "Attributes": {
            "component_id": {"S": "comp-x"},
            "lifecycle_status": {"S": target_status},
        }
    }
    return fake


class ClosedCountGateTests(unittest.TestCase):
    """DESIGNS edge advance gate (approved->designed) reads task.closed_count."""

    def setUp(self):
        coordination_lambda._COMPONENT_TRANSITION_TABLE_CACHE = None
        self._flag = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def _advance_with_closed_count(self, closed_count):
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "approved"},
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X01", "relationship_type": "designs"}],
        ), mock.patch.object(
            coordination_lambda, "_get_task_record",
            return_value={
                "item_id": "ENC-TSK-X01",
                "status": "closed",
                "closed_count": closed_count,
            },
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=_fake_ddb("designed")
        ):
            return coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "designed"}), AGENT_CLAIMS
            )

    def test_gate_fails_when_closed_count_is_zero(self):
        """approved->designed gate: closed_count=0 fails with GATE_CONDITION_UNMET."""
        resp = self._advance_with_closed_count(0)
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "GATE_CONDITION_UNMET")
        self.assertEqual(body["observed_value"], 0)

    def test_gate_passes_when_closed_count_is_one(self):
        """approved->designed gate: closed_count=1 passes (task->closed incremented it)."""
        resp = self._advance_with_closed_count(1)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "designed")

    def test_gate_passes_when_closed_count_is_greater_than_one(self):
        """closed_count=3 (multiple close cycles) also passes the gate."""
        resp = self._advance_with_closed_count(3)
        self.assertEqual(resp["statusCode"], 200)

    def test_gate_fails_when_task_not_closed_despite_count(self):
        """closed_count is the gate criterion — not task status."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "approved"},
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X01", "relationship_type": "designs"}],
        ), mock.patch.object(
            coordination_lambda, "_get_task_record",
            return_value={
                "item_id": "ENC-TSK-X01",
                "status": "in-progress",
                "closed_count": 0,  # the counter is what matters
            },
        ):
            resp = coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "designed"}), AGENT_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "GATE_CONDITION_UNMET")


class CheckoutCountGateTests(unittest.TestCase):
    """IMPLEMENTS edge advance gate (designed->development) reads task.checkout_count."""

    def setUp(self):
        coordination_lambda._COMPONENT_TRANSITION_TABLE_CACHE = None
        self._flag = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def _advance_with_checkout_count(self, checkout_count):
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value={"component_id": "comp-x", "lifecycle_status": "designed"},
        ), mock.patch.object(
            coordination_lambda, "_query_component_edges",
            return_value=[{"target_id": "ENC-TSK-X02", "relationship_type": "implements"}],
        ), mock.patch.object(
            coordination_lambda, "_get_task_record",
            return_value={
                "item_id": "ENC-TSK-X02",
                "status": "in-progress",
                "checkout_count": checkout_count,
            },
        ), mock.patch.object(
            coordination_lambda, "_get_ddb", return_value=_fake_ddb("development")
        ):
            return coordination_lambda._handle_components_advance(
                "comp-x", _event({"target_status": "development"}), AGENT_CLAIMS
            )

    def test_gate_fails_when_checkout_count_is_zero(self):
        """designed->development gate: checkout_count=0 fails with GATE_CONDITION_UNMET."""
        resp = self._advance_with_checkout_count(0)
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "GATE_CONDITION_UNMET")

    def test_gate_passes_when_checkout_count_is_one(self):
        """designed->development gate: checkout_count=1 passes (checkout.task incremented it)."""
        resp = self._advance_with_checkout_count(1)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "development")

    def test_gate_passes_when_checkout_count_is_greater_than_one(self):
        """checkout_count=5 (multiple checkout cycles) also passes the gate."""
        resp = self._advance_with_checkout_count(5)
        self.assertEqual(resp["statusCode"], 200)


class EdgeLockCounterTests(unittest.TestCase):
    """Counter thresholds control edge mutability after creation."""

    def setUp(self):
        coordination_lambda._COMPONENT_TRANSITION_TABLE_CACHE = None
        self._flag = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def test_designs_edge_unlocked_at_closed_count_zero(self):
        """DESIGNS edge: closed_count=0 means edge is NOT locked (remove succeeds)."""
        class _TXE(Exception):
            pass
        fake = mock.MagicMock()
        fake.exceptions.TransactionCanceledException = _TXE
        fake.transact_write_items.return_value = {}
        with mock.patch.object(
            coordination_lambda, "_get_task_record",
            return_value={
                "item_id": "ENC-TSK-X01",
                "closed_count": 0,
                "project_id": "enceladus",
            },
        ), mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value={"component_id": "comp-x", "project_id": "enceladus"},
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_remove_edge(
                "comp-x",
                _event({"edge_type": "DESIGNS", "task_id": "ENC-TSK-X01"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 200)
        self.assertTrue(json.loads(resp["body"])["removed"])

    def test_designs_edge_locked_at_closed_count_one(self):
        """DESIGNS edge: closed_count=1 (task was closed) locks the edge."""
        with mock.patch.object(
            coordination_lambda, "_get_task_record",
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

    def test_implements_edge_unlocked_at_checkout_count_zero(self):
        """IMPLEMENTS edge: checkout_count=0 means edge is NOT locked."""
        class _TXE(Exception):
            pass
        fake = mock.MagicMock()
        fake.exceptions.TransactionCanceledException = _TXE
        fake.transact_write_items.return_value = {}
        with mock.patch.object(
            coordination_lambda, "_get_task_record",
            return_value={
                "item_id": "ENC-TSK-X02",
                "checkout_count": 0,
                "project_id": "enceladus",
            },
        ), mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value={"component_id": "comp-x", "project_id": "enceladus"},
        ), mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_remove_edge(
                "comp-x",
                _event({"edge_type": "IMPLEMENTS", "task_id": "ENC-TSK-X02"}),
                AGENT_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 200)

    def test_implements_edge_locked_at_checkout_count_one(self):
        """IMPLEMENTS edge: checkout_count=1 (task was checked out) locks the edge."""
        with mock.patch.object(
            coordination_lambda, "_get_task_record",
            return_value={"item_id": "ENC-TSK-X02", "checkout_count": 1},
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


class ReservedFieldGuardTests(unittest.TestCase):
    """tracker_mutation must reject direct writes to counter fields (400 RESERVED_FIELD)."""

    def test_direct_write_to_closed_count_returns_400(self):
        """tracker.set closed_count directly: 400 RESERVED_FIELD."""
        body = {"field": "closed_count", "value": 7, "provider": "agent-x"}
        result = tracker_mutation._handle_update_field(
            "enceladus", "task", "ENC-TSK-001", body
        )
        self.assertEqual(result.get("statusCode"), 400)
        body_dict = json.loads(result.get("body", "{}"))
        envelope = body_dict.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "RESERVED_FIELD")
        self.assertEqual(envelope.get("details", {}).get("field"), "closed_count")

    def test_direct_write_to_checkout_count_returns_400(self):
        """tracker.set checkout_count directly: 400 RESERVED_FIELD."""
        body = {"field": "checkout_count", "value": 42, "provider": "agent-y"}
        result = tracker_mutation._handle_update_field(
            "enceladus", "task", "ENC-TSK-001", body
        )
        self.assertEqual(result.get("statusCode"), 400)
        body_dict = json.loads(result.get("body", "{}"))
        envelope = body_dict.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "RESERVED_FIELD")
        self.assertEqual(envelope.get("details", {}).get("field"), "checkout_count")

    def test_reserved_field_guard_fires_before_ddb_access(self):
        """The guard must fire before any DDB read — no DB round-trip for rejected fields."""
        mock_ddb = mock.MagicMock()
        with mock.patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = tracker_mutation._handle_update_field(
                "enceladus", "task", "ENC-TSK-001",
                {"field": "closed_count", "value": 5, "provider": "x"},
            )
        self.assertEqual(result.get("statusCode"), 400)
        mock_ddb.update_item.assert_not_called()
        mock_ddb.get_item.assert_not_called()

    def test_reserved_field_guard_on_create_closed_count(self):
        """tracker.create with closed_count in body: 400 RESERVED_FIELD."""
        result = tracker_mutation._handle_create_record(
            "enceladus", "task",
            {
                "title": "Test",
                "acceptance_criteria": [{"description": "x"}],
                "closed_count": 99,
            },
        )
        self.assertEqual(result.get("statusCode"), 400)
        body_dict = json.loads(result.get("body", "{}"))
        envelope = body_dict.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "RESERVED_FIELD")

    def test_reserved_field_guard_on_create_checkout_count(self):
        """tracker.create with checkout_count in body: 400 RESERVED_FIELD."""
        result = tracker_mutation._handle_create_record(
            "enceladus", "task",
            {
                "title": "Test",
                "acceptance_criteria": [{"description": "x"}],
                "checkout_count": 12,
            },
        )
        self.assertEqual(result.get("statusCode"), 400)
        body_dict = json.loads(result.get("body", "{}"))
        envelope = body_dict.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "RESERVED_FIELD")

    def test_reserved_field_constant_contains_both_fields(self):
        """_F41_RESERVED_COUNTER_FIELDS frozenset must contain both counter names."""
        self.assertIn("closed_count", tracker_mutation._F41_RESERVED_COUNTER_FIELDS)
        self.assertIn("checkout_count", tracker_mutation._F41_RESERVED_COUNTER_FIELDS)


if __name__ == "__main__":
    unittest.main()
