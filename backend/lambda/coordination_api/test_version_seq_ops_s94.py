"""test_version_seq_ops_s94.py -- coordination_api sequences its status writes
(ENC-TSK-S94 / ENC-ISS-908).

_set_tracker_status is the highest-blast-radius DynamoDB writer in the codebase and
it allocated no version_seq, so every status it set -- closes included -- was
invisible to the Query on version-seq-index behind GET /api/v1/feed/delta. It also
never added closed_count, the gate evidence for component.advance
approved -> designed (ENC-FTR-076).

These tests pin the two properties that keep the fix safe to deploy:
  * the SET fragment stamps write_kind exactly once and never emits an ADD, and
  * sequencing is BEST-EFFORT -- the pinned shared layer (enceladus-shared:15) does
    not carry the rule yet, and a counter failure must leave the governed status
    write intact rather than failing a lifecycle terminal.

Run: python3 -m pytest test_version_seq_ops_s94.py -q
"""

from __future__ import annotations

import os
import sys
import unittest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

import version_seq_ops as vso  # noqa: E402


class _FakeDdb:
    def __init__(self, start=500, boom=False):
        self._next = start
        self.boom = boom
        self.calls = []

    def update_item(self, **kwargs):
        self.calls.append(kwargs)
        if self.boom:
            raise RuntimeError("counter unavailable")
        self._next += 1
        return {"Attributes": {"next_num": {"N": str(self._next)}}}


class SequencedWritePartsTests(unittest.TestCase):
    def test_fragment_is_appendable_and_stamps_write_kind_once(self):
        expr, values = vso.sequenced_write_parts(_FakeDdb(), "t")
        self.assertTrue(expr.startswith(", "), expr)
        self.assertNotIn(" ADD ", expr)
        self.assertEqual(1, expr.count("write_kind ="), expr)
        self.assertEqual(1, expr.count("version_seq ="), expr)
        self.assertEqual({"S": "governed"}, values[":vsq_wkind"])

    def test_allocation_failure_fails_open(self):
        """A lifecycle status write must not fail for want of a sequence number."""
        expr, values = vso.sequenced_write_parts(_FakeDdb(boom=True), "t")
        self.assertEqual(", write_kind = :vsq_wkind", expr)
        self.assertEqual({"S": "governed"}, values[":vsq_wkind"])
        self.assertNotIn("version_seq", expr)

    def test_a_sequencing_rule_is_reachable(self):
        """Either the rule or the primitives layer :15 carries must resolve."""
        self.assertIn(
            vso.SEQUENCING_SOURCE,
            ("shared_layer_rule", "shared_layer_primitives"),
            "neither the shared rule nor its primitives were importable")


class ClosedCountAddPartsTests(unittest.TestCase):
    def test_task_close_adds_closed_count(self):
        expr, values = vso.closed_count_add_parts("task", "closed")
        self.assertEqual(" ADD closed_count :vsq_cc_one", expr)
        self.assertEqual({"N": "1"}, values[":vsq_cc_one"])

    def test_non_close_and_non_task_add_nothing(self):
        for record_type, status in (
            ("task", "in-progress"), ("task", "merged-main"),
            ("issue", "closed"), ("feature", "closed"),
            ("", "closed"), ("task", ""),
        ):
            expr, values = vso.closed_count_add_parts(record_type, status)
            self.assertEqual("", expr, f"{record_type}/{status}")
            self.assertEqual({}, values)

    def test_matching_is_case_and_space_insensitive(self):
        expr, _v = vso.closed_count_add_parts(" Task ", " CLOSED ")
        self.assertEqual(" ADD closed_count :vsq_cc_one", expr)


class ComposedExpressionTests(unittest.TestCase):
    """SET before ADD, always (ENC-TSK-P49)."""

    def test_set_fragment_precedes_add_clause(self):
        vseq_expr, _vals = vso.sequenced_write_parts(_FakeDdb(), "t")
        cc_expr, _cc = vso.closed_count_add_parts("task", "closed")
        expr = (
            "SET #status = :new_status, updated_at = :ts, last_update_note = :note, "
            "sync_version = if_not_exists(sync_version, :zero) + :one"
            + vseq_expr + cc_expr
        )
        set_half, add_half = expr.split(" ADD ", 1)
        self.assertIn("version_seq =", set_half)
        self.assertIn("write_kind =", set_half)
        self.assertNotIn("=", add_half)
        self.assertEqual("closed_count :vsq_cc_one", add_half)


if __name__ == "__main__":
    unittest.main()
