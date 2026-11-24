"""test_close_sequencing_s94.py -- every task close allocates a version_seq
(ENC-TSK-S94 / ENC-ISS-908).

WHAT THIS GUARDS. Status closed was written to tasks by seven code paths and only
two of them allocated a version_seq: the generic PATCH behind checkout.advance and
the PWA legacy close. The other five wrote the close with no sequence number, and
GET /api/v1/feed/delta is a Query on the version-seq-index GSI
(feed_scope = global AND version_seq > :cursor), so an unsequenced close is
invisible to the pull path -- a client that missed the push event could not heal
that record until its next sequenced write. Two of the five (coordination_api
_set_tracker_status and bedrock_agent_actions _handle_tracker_status) also never
added closed_count, the gate evidence for component.advance approved -> designed
(ENC-FTR-076).

The remediation routes every site through ONE rule,
enceladus_shared.version_seq.sequenced_governed_write_parts (bundled fallback in
version_seq_util), which returns an appendable SET fragment that stamps
version_seq, feed_scope and write_kind together.

TWO TRAPS THESE TESTS FENCE:
  * ENC-TSK-P49 -- the fragment is a SET assignment and must be spliced BEFORE any
    ADD clause. "SET ... ADD closed_count :one, version_seq = :vseq" is a
    DynamoDB ValidationException, and it once broke every governed task close.
  * ENC-ISS-759 -- the fragment stamps write_kind, so a site that also assigns
    write_kind names one document path twice ("Two document paths overlap").
    _render_update_expression now checks the fragment's paths too, so the defect
    fails in-process instead of at a live UpdateItem.

Run: python3 -m pytest test_close_sequencing_s94.py -q
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
import unittest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

_HERE = os.path.dirname(__file__)
sys.path.insert(0, _HERE)
_spec = importlib.util.spec_from_file_location(
    "tracker_mutation_close_sequencing_s94",
    os.path.join(_HERE, "lambda_function.py"),
)
tm = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)


def _set_clause(expr: str) -> str:
    """The SET half of an UpdateExpression (everything before ' ADD ')."""
    return expr.split(" ADD ", 1)[0]


def _add_clause(expr: str) -> str:
    return expr.split(" ADD ", 1)[1] if " ADD " in expr else ""


class _FakeDdb:
    """Captures update_item calls; answers the version_seq counter allocation."""

    def __init__(self, start: int = 4200):
        self.calls = []
        self._next = start

    def update_item(self, **kwargs):
        self.calls.append(kwargs)
        key = kwargs.get("Key") or {}
        if key.get("record_id", {}).get("S") == "counter#version_seq":
            self._next += 1
            return {"Attributes": {"next_num": {"N": str(self._next)}}}
        return {}

    @property
    def record_writes(self):
        return [c for c in self.calls
                if (c.get("Key") or {}).get("record_id", {}).get("S")
                != "counter#version_seq"]


class SequencingRuleTests(unittest.TestCase):
    """The rule itself, in both homes, must agree."""

    def _assert_fragment(self, expr, values, seq):
        self.assertTrue(expr.startswith(", "),
                        f"fragment must be appendable onto a SET clause: {expr!r}")
        self.assertNotIn(" ADD ", expr, "the rule must never emit an ADD clause")
        self.assertEqual(expr.count("version_seq ="), 1)
        self.assertEqual(expr.count("feed_scope ="), 1)
        self.assertEqual(expr.count("write_kind ="), 1)
        self.assertEqual(values[":vseq"], {"N": str(seq)})
        self.assertEqual(values[":vsq_wkind"], {"S": "governed"})

    def test_shared_layer_rule(self):
        from enceladus_shared import version_seq as shared
        ddb = _FakeDdb()
        expr, values, seq = shared.sequenced_governed_write_parts(ddb, "t")
        self._assert_fragment(expr, values, seq)

    def test_bundled_rule_matches_shared(self):
        import version_seq_util as bundled
        from enceladus_shared import version_seq as shared
        a_expr, _a, _as = bundled.sequenced_governed_write_parts(_FakeDdb(), "t")
        b_expr, _b, _bs = shared.sequenced_governed_write_parts(_FakeDdb(), "t")
        self.assertEqual(a_expr, b_expr,
                         "bundled and shared copies of the rule must not drift")

    def test_version_seq_is_a_cursor_not_a_counter(self):
        """A burned number is legal: allocation precedes the conditional write."""
        from enceladus_shared import version_seq as shared
        ddb = _FakeDdb()
        _e1, _v1, s1 = shared.sequenced_governed_write_parts(ddb, "t")
        _e2, _v2, s2 = shared.sequenced_governed_write_parts(ddb, "t")
        self.assertGreater(s2, s1, "the sequence must be monotone")

    def test_pure_composer_matches_the_allocating_wrapper(self):
        """tracker_mutation keeps its allocator seam and shares only composition."""
        from enceladus_shared import version_seq as shared
        expr_pure, vals_pure = shared.sequenced_governed_write_clause(77)
        expr_alloc, vals_alloc, seq = shared.sequenced_governed_write_parts(
            _FakeDdb(start=76), "t")
        self.assertEqual(77, seq)
        self.assertEqual(expr_pure, expr_alloc)
        self.assertEqual(vals_pure, vals_alloc)


class RenderUpdateExpressionTests(unittest.TestCase):
    """_render_update_expression keeps the fragment inside SET and before ADD."""

    def test_suffix_is_spliced_before_add(self):
        expr = tm._render_update_expression(
            [("status", "#st = :s")],
            ["closed_count :one"],
            set_suffix=", version_seq = :vseq, write_kind = :wkind",
        )
        self.assertIn("version_seq = :vseq", _set_clause(expr))
        self.assertEqual("closed_count :one", _add_clause(expr))
        self.assertIsNone(
            re.search(r" ADD .*=", expr),
            f"no SET assignment may appear after ADD (ENC-TSK-P49): {expr!r}")

    def test_suffix_path_collision_raises(self):
        with self.assertRaises(ValueError):
            tm._render_update_expression(
                [("write_kind", "write_kind = :wk")],
                None,
                set_suffix=", write_kind = :wkind",
            )

    def test_no_suffix_is_unchanged(self):
        self.assertEqual(
            "SET #st = :s",
            tm._render_update_expression([("status", "#st = :s")]))

    def test_sequencing_paths_are_reserved_from_escalation_field_values(self):
        for path in ("version_seq", "feed_scope", "t_ack", "projection_status"):
            self.assertIn(path, tm._RESERVED_OVERRIDE_PATHS)


class EscalationCloseIsSequencedTests(unittest.TestCase):
    """Site 1 of 5, behavioural: the escalated direct_state_override close."""

    def setUp(self):
        self.ddb = _FakeDdb()
        self._real_get_ddb = tm._get_ddb
        tm._get_ddb = lambda: self.ddb
        self.addCleanup(setattr, tm, "_get_ddb", self._real_get_ddb)

    def _close(self, record_type="task"):
        tm._apply_direct_state_override(
            "enceladus",
            {"item_id": "ENC-ESC-999",
             "payload": {"target_status": "closed", "field_values": {}}},
            {"item_id": "ENC-TSK-S94", "record_type": record_type,
             "status": "merged-main"},
        )
        writes = self.ddb.record_writes
        self.assertEqual(len(writes), 1)
        return writes[0]

    def test_close_allocates_version_seq_exactly_once(self):
        call = self._close()
        expr = call["UpdateExpression"]
        self.assertEqual(expr.count("version_seq ="), 1, expr)
        self.assertEqual(expr.count("write_kind ="), 1,
                         f"write_kind must be stamped once, not twice: {expr!r}")
        self.assertIn(":vseq", call["ExpressionAttributeValues"])
        self.assertEqual(
            {"S": "governed"},
            call["ExpressionAttributeValues"][":vsq_wkind"])

    def test_close_keeps_set_before_add(self):
        expr = self._close()["UpdateExpression"]
        self.assertIn("version_seq =", _set_clause(expr))
        self.assertIn("closed_count", _add_clause(expr))
        self.assertIsNone(re.search(r" ADD .*=", expr), expr)

    def test_non_task_close_is_sequenced_without_closed_count(self):
        expr = self._close(record_type="issue")["UpdateExpression"]
        self.assertEqual(expr.count("version_seq ="), 1, expr)
        self.assertNotIn("closed_count", expr,
                         "only tasks carry closed_count")


class CloseSiteStructureTests(unittest.TestCase):
    """Sites 2 and 3: the arc-walker and human-override expressions are built by
    string concatenation inside large handlers, so they are fenced structurally
    here and proved behaviourally on gamma (DOC-5E1E205FA664 criterion 18)."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(_HERE, "lambda_function.py"), encoding="utf-8") as fh:
            cls.src = fh.read()

    def test_arc_walker_splices_sequencing_before_add(self):
        self.assertIn("+ extra_set + _aw_vseq_expr + add_clause", self.src)
        self.assertNotIn(
            'SET write_kind = :wk, #s = :next', self.src,
            "the arc-walker must no longer stamp write_kind itself")

    def test_human_override_splices_sequencing_before_add(self):
        self.assertIn("ui_update_expr += _ui_vseq_expr", self.src)
        self.assertLess(
            self.src.index("ui_update_expr += _ui_vseq_expr"),
            self.src.index('ui_update_expr += " ADD closed_count :one"'),
            "the sequencing fragment must be appended before the ADD clause")
        self.assertNotIn(
            'SET write_kind = :wk, #fld = :val', self.src,
            "the human override must no longer stamp write_kind itself")

    def test_the_three_formerly_unsequenced_sites_bind_the_rule(self):
        """Each previously-unsequenced close site now takes the fragment.

        They bind through _sequencing_parts_or_governed(), the fail-open wrapper:
        none of the three allocates inside the try/except guarding its own write,
        and the arc-walker would otherwise let a counter ClientError escape its
        walk loop. A close must not fail for want of a sequence number.
        """
        for binding, site in (
            ("_esc_vseq_expr, _esc_vseq_vals = _sequencing_parts_or_governed()",
             "escalation direct_state_override"),
            ("_aw_vseq_expr, _aw_vseq_vals = _sequencing_parts_or_governed()",
             "arc-walker code_only close"),
            ("_ui_vseq_expr, _ui_vseq_vals = _sequencing_parts_or_governed()",
             "human-override advance"),
        ):
            self.assertEqual(
                1, self.src.count(binding),
                f"{site} must bind the sequencing fragment exactly once")


class SequencingFailsOpenTests(unittest.TestCase):
    """A counter failure must not take down a close (ENC-TSK-S94)."""

    def test_allocation_failure_still_stamps_write_kind(self):
        real = tm._version_seq_update_parts

        def boom():
            raise RuntimeError("counter unavailable")

        tm._version_seq_update_parts = boom
        self.addCleanup(setattr, tm, "_version_seq_update_parts", real)
        expr, values = tm._sequencing_parts_or_governed()
        self.assertEqual(", write_kind = :vsq_wkind", expr)
        self.assertEqual({"S": "governed"}, values[":vsq_wkind"])
        self.assertNotIn("version_seq", expr)

    def test_escalation_close_survives_allocation_failure(self):
        real = tm._version_seq_update_parts
        ddb = _FakeDdb()
        real_get = tm._get_ddb
        tm._get_ddb = lambda: ddb
        self.addCleanup(setattr, tm, "_get_ddb", real_get)

        def boom():
            raise RuntimeError("counter unavailable")

        tm._version_seq_update_parts = boom
        self.addCleanup(setattr, tm, "_version_seq_update_parts", real)
        tm._apply_direct_state_override(
            "enceladus",
            {"item_id": "ENC-ESC-999",
             "payload": {"target_status": "closed", "field_values": {}}},
            {"item_id": "ENC-TSK-S94", "record_type": "task",
             "status": "merged-main"},
        )
        writes = ddb.record_writes
        self.assertEqual(len(writes), 1, "the close must still land")
        expr = writes[0]["UpdateExpression"]
        self.assertEqual(expr.count("write_kind ="), 1, expr)
        self.assertNotIn("version_seq", expr)


if __name__ == "__main__":
    unittest.main()
