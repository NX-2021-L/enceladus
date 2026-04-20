"""test_counter_fields.py — Tests for ENC-TSK-F41 / FTR-076 v2 task counter fields.

Covers the four AC[1e] cases defined on ENC-TSK-F41 (DOC-546B896390EA §5):

  1. Close transition increments closed_count atomically (ADD :one on status->closed).
  2. Successful checkout.task invocation increments checkout_count atomically
     (ADD :one on active_agent_session=True for task records).
  3. tracker.set and tracker.create reject direct writes to either counter field
     with HTTP 400 error_envelope.code=RESERVED_FIELD.
  4. Multiple transitions accumulate counts correctly — each :one ADD issues on
     each lifecycle transition, so N cycles of checkout+close produce checkout_count=N
     and closed_count=N without coalescing.

Also validates the PWA user-initiated close path, the legacy PWA action=close path,
and the task-create stamping of default counter values.

Run: python3 -m pytest test_counter_fields.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location(
    "tracker_mutation",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tracker_mutation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tracker_mutation)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_ddb_task(status="open", item_id="ENC-TSK-001", checkout_count=0,
                   closed_count=0, checked_out_by=None, extra=None):
    """Return a DynamoDB-style raw task item including the F41 counter fields."""
    item = {
        "project_id": {"S": "enceladus"},
        "record_id": {"S": f"task#{item_id}"},
        "item_id": {"S": item_id},
        "status": {"S": status},
        "record_type": {"S": "task"},
        "sync_version": {"N": "1"},
        "history": {"L": []},
        "checkout_count": {"N": str(checkout_count)},
        "closed_count": {"N": str(closed_count)},
    }
    if checked_out_by:
        item["active_agent_session"] = {"BOOL": True}
        item["active_agent_session_id"] = {"S": checked_out_by}
        item["checkout_state"] = {"S": "checked_out"}
        item["checked_out_by"] = {"S": checked_out_by}
    if extra:
        item.update(extra)
    return item


def _call_update_field(project_id, record_type, record_id, body):
    return tracker_mutation._handle_update_field(project_id, record_type, record_id, body)


def _captured_update_expression(mock_ddb):
    """Return the UpdateExpression string from the last update_item call."""
    self_kwargs = mock_ddb.update_item.call_args.kwargs
    return self_kwargs.get("UpdateExpression", "")


# ---------------------------------------------------------------------------
# AC[1e]-c (part 1): tracker.set rejects direct writes with 400 RESERVED_FIELD
# ---------------------------------------------------------------------------

class TestReservedFieldGuardOnUpdate(unittest.TestCase):
    """tracker.set (PATCH) must reject closed_count / checkout_count writes."""

    def test_set_closed_count_direct_write_rejected(self):
        body = {"field": "closed_count", "value": 7, "provider": "attacker-agent"}
        result = _call_update_field("enceladus", "task", "ENC-TSK-001", body)
        self.assertEqual(result.get("statusCode"), 400)
        body_dict = json.loads(result.get("body", "{}"))
        self.assertFalse(body_dict.get("success"))
        envelope = body_dict.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "RESERVED_FIELD")
        self.assertEqual(envelope.get("details", {}).get("field"), "closed_count")
        self.assertEqual(envelope.get("details", {}).get("reason"), "server_side_only")
        self.assertIn("ENC-TSK-F41", envelope.get("details", {}).get("rule_citation", ""))

    def test_set_checkout_count_direct_write_rejected(self):
        body = {"field": "checkout_count", "value": 42, "provider": "attacker-agent"}
        result = _call_update_field("enceladus", "task", "ENC-TSK-001", body)
        self.assertEqual(result.get("statusCode"), 400)
        body_dict = json.loads(result.get("body", "{}"))
        envelope = body_dict.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "RESERVED_FIELD")
        self.assertEqual(envelope.get("details", {}).get("field"), "checkout_count")
        self.assertIn("DOC-546B896390EA", envelope.get("details", {}).get("rule_citation", ""))

    def test_guard_precedes_ddb_read(self):
        """The reserved-field guard must fire before any DDB interaction."""
        mock_ddb = MagicMock()
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field(
                "enceladus", "task", "ENC-TSK-001",
                {"field": "closed_count", "value": 5, "provider": "x"},
            )
        self.assertEqual(result.get("statusCode"), 400)
        mock_ddb.update_item.assert_not_called()
        mock_ddb.get_item.assert_not_called()


# ---------------------------------------------------------------------------
# AC[1e]-c (part 2): tracker.create rejects body keys with 400 RESERVED_FIELD
# ---------------------------------------------------------------------------

class TestReservedFieldGuardOnCreate(unittest.TestCase):
    """tracker.create must reject bodies that include closed_count / checkout_count."""

    def _create_body(self, **extras):
        body = {
            "title": "Test task",
            "acceptance_criteria": [{"description": "Thing happens"}],
        }
        body.update(extras)
        return body

    def test_create_with_closed_count_rejected(self):
        result = tracker_mutation._handle_create_record(
            "enceladus", "task", self._create_body(closed_count=99),
        )
        self.assertEqual(result.get("statusCode"), 400)
        body_dict = json.loads(result.get("body", "{}"))
        envelope = body_dict.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "RESERVED_FIELD")
        self.assertEqual(envelope.get("details", {}).get("field"), "closed_count")

    def test_create_with_checkout_count_rejected(self):
        result = tracker_mutation._handle_create_record(
            "enceladus", "task", self._create_body(checkout_count=12),
        )
        self.assertEqual(result.get("statusCode"), 400)
        body_dict = json.loads(result.get("body", "{}"))
        envelope = body_dict.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "RESERVED_FIELD")
        self.assertEqual(envelope.get("details", {}).get("field"), "checkout_count")


# ---------------------------------------------------------------------------
# AC[1e]-a: close transition increments closed_count atomically
# ---------------------------------------------------------------------------

class TestCloseIncrementsClosedCount(unittest.TestCase):
    """status -> closed transition must append `ADD closed_count :one` to the
    same UpdateExpression that SETs the status field. Atomic by construction."""

    def _transition_to_closed(self, current_status, live_evidence="smoke-ok"):
        body = {
            "field": "status",
            "value": "closed",
            "provider": "codex",
            "transition_evidence": {"live_validation_evidence": live_evidence},
        }
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_ddb_task(status=current_status, checked_out_by="codex")
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            with patch.object(tracker_mutation, "_validate_commit_via_github",
                              return_value=(True, "ok")):
                result = _call_update_field(
                    "enceladus", "task", "ENC-TSK-001", body,
                )
        return mock_ddb, json.loads(result.get("body", "{}"))

    def test_deploy_success_to_closed_adds_closed_count(self):
        mock_ddb, body = self._transition_to_closed("deploy-success")
        self.assertTrue(body.get("success"))
        expr = _captured_update_expression(mock_ddb)
        self.assertIn("ADD closed_count :one", expr)
        self.assertIn(":one", mock_ddb.update_item.call_args.kwargs["ExpressionAttributeValues"])
        self.assertEqual(
            mock_ddb.update_item.call_args.kwargs["ExpressionAttributeValues"][":one"],
            {"N": "1"},
        )

    def test_non_closed_transition_does_not_add_closed_count(self):
        """Transitions to non-closed statuses must not bump closed_count."""
        body = {"field": "status", "value": "coding-complete", "provider": "codex"}
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_ddb_task(status="in-progress", checked_out_by="codex"),
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            with patch.object(tracker_mutation, "_validate_commit_via_github",
                              return_value=(True, "ok")):
                _call_update_field("enceladus", "task", "ENC-TSK-001", body)
        expr = _captured_update_expression(mock_ddb)
        self.assertNotIn("closed_count", expr)

    def test_non_task_close_does_not_add_closed_count(self):
        """Feature / issue closures (non-task record types) do not carry the
        closed_count field; ADD must be scoped to tasks only."""
        body = {"field": "status", "value": "closed", "provider": "codex"}
        mock_ddb = MagicMock()
        feature_item = _mock_ddb_task(status="development", checked_out_by="codex")
        feature_item["record_type"] = {"S": "feature"}
        feature_item["record_id"] = {"S": "feature#ENC-FTR-001"}
        mock_ddb.get_item.return_value = {"Item": feature_item}
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            with patch.object(tracker_mutation, "_validate_commit_via_github",
                              return_value=(True, "ok")):
                _call_update_field("enceladus", "feature", "ENC-FTR-001", body)
        # No update_item call means the feature lifecycle rejected the transition,
        # which is acceptable. If it did call update_item, closed_count must not
        # be referenced in the expression.
        if mock_ddb.update_item.called:
            expr = _captured_update_expression(mock_ddb)
            self.assertNotIn("closed_count", expr)


# ---------------------------------------------------------------------------
# AC[1e]-a (PWA path): legacy action=close on a task bumps closed_count
# ---------------------------------------------------------------------------

class TestPwaCloseIncrementsClosedCount(unittest.TestCase):
    """The legacy _handle_pwa_action close path also bumps closed_count for tasks."""

    def test_pwa_action_close_task_adds_closed_count(self):
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_ddb_task(status="in-progress"),
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            with patch.object(tracker_mutation, "_get_record_full",
                              return_value={
                                  "status": "in-progress",
                                  "sync_version": 1,
                                  "record_id": "task#ENC-TSK-001",
                              }):
                result = tracker_mutation._handle_pwa_action(
                    "enceladus", "task", "ENC-TSK-001",
                    {"action": "close"}, "close",
                )
        self.assertEqual(result.get("statusCode"), 200)
        expr = _captured_update_expression(mock_ddb)
        self.assertIn("ADD closed_count :one", expr)


# ---------------------------------------------------------------------------
# AC[1e]-b: successful checkout bumps checkout_count atomically
# ---------------------------------------------------------------------------

class TestCheckoutIncrementsCheckoutCount(unittest.TestCase):
    """Successful checkout (field=active_agent_session, value=True, record_type=task)
    must append `ADD checkout_count :one` to the same UpdateExpression."""

    def test_successful_checkout_adds_checkout_count(self):
        body = {
            "field": "active_agent_session",
            "value": True,
            "provider": "claude-code",
        }
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_ddb_task(status="open"),
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field(
                "enceladus", "task", "ENC-TSK-001", body,
            )
        body_dict = json.loads(result.get("body", "{}"))
        self.assertTrue(body_dict.get("success"))
        expr = _captured_update_expression(mock_ddb)
        self.assertIn("ADD checkout_count :one", expr)
        attr_values = mock_ddb.update_item.call_args.kwargs["ExpressionAttributeValues"]
        self.assertEqual(attr_values[":one"], {"N": "1"})

    def test_release_does_not_bump_checkout_count(self):
        """Release (value=False) must not increment checkout_count."""
        body = {
            "field": "active_agent_session",
            "value": False,
            "provider": "claude-code",
        }
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_ddb_task(status="in-progress", checked_out_by="claude-code"),
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            _call_update_field("enceladus", "task", "ENC-TSK-001", body)
        expr = _captured_update_expression(mock_ddb)
        self.assertNotIn("checkout_count", expr)

    def test_non_task_checkout_does_not_bump_checkout_count(self):
        """Plan / feature checkouts do not carry a checkout_count field; ADD must
        be scoped to tasks only."""
        body = {
            "field": "active_agent_session",
            "value": True,
            "provider": "coord-lead",
        }
        mock_ddb = MagicMock()
        plan_item = _mock_ddb_task(status="drafted")
        plan_item["record_type"] = {"S": "plan"}
        plan_item["record_id"] = {"S": "plan#ENC-PLN-001"}
        mock_ddb.get_item.return_value = {"Item": plan_item}
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            _call_update_field("enceladus", "plan", "ENC-PLN-001", body)
        if mock_ddb.update_item.called:
            expr = _captured_update_expression(mock_ddb)
            self.assertNotIn("checkout_count", expr)


# ---------------------------------------------------------------------------
# AC[1e]-e (4): multiple transitions accumulate counts correctly
# ---------------------------------------------------------------------------

class TestCounterAccumulation(unittest.TestCase):
    """Every lifecycle transition issues its own atomic ADD :one operation, so
    N checkout+close cycles produce checkout_count=N and closed_count=N at the
    DDB layer. This test verifies the emitted update expressions accumulate
    rather than coalescing (one ADD per transition call)."""

    def test_three_checkouts_emit_three_add_operations(self):
        """Three sequential checkout calls each emit an ADD checkout_count :one."""
        body = {
            "field": "active_agent_session",
            "value": True,
            "provider": "agent-x",
        }
        mock_ddb = MagicMock()
        # On each call, simulate the counter having advanced by the prior ADDs.
        responses = [
            {"Item": _mock_ddb_task(status="open", checkout_count=0)},
            {"Item": _mock_ddb_task(status="open", checkout_count=1)},
            {"Item": _mock_ddb_task(status="open", checkout_count=2)},
        ]
        mock_ddb.get_item.side_effect = responses
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            for _ in range(3):
                _call_update_field(
                    "enceladus", "task", "ENC-TSK-001", dict(body),
                )
        # Each call emits one ADD checkout_count :one clause.
        add_counts = [
            "ADD checkout_count :one" in call.kwargs.get("UpdateExpression", "")
            for call in mock_ddb.update_item.call_args_list
        ]
        self.assertEqual(add_counts, [True, True, True])

    def test_two_close_transitions_emit_two_add_operations(self):
        """Two close transitions (e.g. close, reopen+close cycle) each emit ADD closed_count :one."""
        body = {
            "field": "status",
            "value": "closed",
            "provider": "codex",
            "transition_evidence": {"live_validation_evidence": "probe ok"},
        }
        mock_ddb = MagicMock()
        responses = [
            {"Item": _mock_ddb_task(status="deploy-success",
                                     checked_out_by="codex",
                                     closed_count=0)},
            {"Item": _mock_ddb_task(status="deploy-success",
                                     checked_out_by="codex",
                                     closed_count=1)},
        ]
        mock_ddb.get_item.side_effect = responses
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            with patch.object(tracker_mutation, "_validate_commit_via_github",
                              return_value=(True, "ok")):
                for _ in range(2):
                    _call_update_field(
                        "enceladus", "task", "ENC-TSK-001", dict(body),
                    )
        add_counts = [
            "ADD closed_count :one" in call.kwargs.get("UpdateExpression", "")
            for call in mock_ddb.update_item.call_args_list
        ]
        self.assertEqual(add_counts, [True, True])


# ---------------------------------------------------------------------------
# Task create stamps counter defaults = 0
# ---------------------------------------------------------------------------

class TestCreateStampsCounterDefaults(unittest.TestCase):
    """tracker.create for a task record must stamp closed_count=0 and
    checkout_count=0 as Number attributes so the ADD semantics and gate reads
    both work from first principles."""

    def test_task_create_includes_counter_defaults(self):
        captured_items = []

        def fake_put_item(TableName, Item, ConditionExpression=None):
            captured_items.append(Item)
            return {}

        mock_ddb = MagicMock()
        mock_ddb.put_item.side_effect = fake_put_item
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            with patch.object(tracker_mutation, "_get_project_prefix",
                              return_value="ENC"):
                with patch.object(tracker_mutation, "_next_record_id",
                                  return_value="ENC-TSK-999"):
                    result = tracker_mutation._handle_create_record(
                        "enceladus", "task",
                        {
                            "title": "Counter defaults task",
                            "acceptance_criteria": [{"description": "x"}],
                        },
                    )
        self.assertEqual(result.get("statusCode"), 201,
                          msg=f"Expected 201, got {result.get('statusCode')}: {result.get('body')}")
        self.assertEqual(len(captured_items), 1)
        item = captured_items[0]
        self.assertIn("closed_count", item, "Task create must stamp closed_count default")
        self.assertIn("checkout_count", item, "Task create must stamp checkout_count default")
        self.assertEqual(item["closed_count"], {"N": "0"})
        self.assertEqual(item["checkout_count"], {"N": "0"})


# ---------------------------------------------------------------------------
# Reserved-field constant is wired
# ---------------------------------------------------------------------------

class TestReservedFieldConstant(unittest.TestCase):
    """Sanity check: the _F41_RESERVED_COUNTER_FIELDS frozenset is the single
    source of truth for the guard and must contain both counter names."""

    def test_constant_contains_both_counter_fields(self):
        self.assertIn("closed_count", tracker_mutation._F41_RESERVED_COUNTER_FIELDS)
        self.assertIn("checkout_count", tracker_mutation._F41_RESERVED_COUNTER_FIELDS)

    def test_constant_is_frozenset(self):
        self.assertIsInstance(tracker_mutation._F41_RESERVED_COUNTER_FIELDS, frozenset)


if __name__ == "__main__":
    unittest.main()
