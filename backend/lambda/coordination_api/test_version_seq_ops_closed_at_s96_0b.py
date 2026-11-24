"""test_closed_at_coordination_s96_0b.py -- coordination_api dates its task closes
(ENC-TSK-S96-0B, ENC-PLN-108 W1.2, ruling D-22).

ENC-TSK-S94 made both _set_tracker_status copies allocate a version_seq and add
closed_count through one shared module. W1.2 extends that module so a close
through either writer also stamps closed_at. Nothing is routed through
tracker_mutation; ruling D-24 fixed the writer count at six, of which these two
are the coordination_api half.

Three properties are pinned here, and the third is the one with teeth:

  * the fragment is SET-only, appendable, and names closed_at exactly once;
  * its predicate is IDENTICAL to the closed_count predicate, so the date and
    the count can never disagree about whether a close happened; and
  * it is INDEPENDENT of the sequencing rule. version_seq_ops imports that rule
    through a three-rung ladder because SharedLayerArn is pinned to a layer that
    may not carry it, and the ":7"/":10" Runtime.ImportModuleError incidents are
    why the ladder exists. closed_at must hold on every rung: a stamp that
    vanished when the layer degraded would read as a task that never closed,
    which is worse than no stamp at all.

Run: python3 -m pytest test_closed_at_coordination_s96_0b.py -q
"""

from __future__ import annotations

import os
import re
import sys
import unittest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

# NOTE ON THIS FILE'S NAME. version_seq_ops resolves its sequencing rule at
# IMPORT time and is then cached in sys.modules, so whichever test module
# imports it first fixes which rung of the ladder every later test observes --
# and importing it with the shared layer on sys.path also leaves
# enceladus_shared cached for every module loaded afterwards. A file named
# test_closed_at_* sorts ahead of test_component_*, which turned 17 collection
# errors into 186 extra discovered tests and made an origin/main baseline
# comparison impossible. These tests cover version_seq_ops, the same module
# test_version_seq_ops_s94.py covers, so the file is named to sit beside it and
# load in the same position. Do not rename it earlier in the alphabet.

import version_seq_ops as vso  # noqa: E402

NOW = "2026-11-19T07:30:00Z"


def _set_clause(expr):
    return expr.split(" ADD ", 1)[0]


def _add_clause(expr):
    return expr.split(" ADD ", 1)[1] if " ADD " in expr else ""


class ClosedAtRuleTests(unittest.TestCase):
    def test_task_close_yields_an_appendable_set_fragment(self):
        expr, values = vso.closed_at_set_parts("task", "closed", NOW)
        self.assertTrue(expr.startswith(", "), expr)
        self.assertNotIn(" ADD ", expr, "the rule must never emit an ADD clause")
        self.assertEqual(1, expr.count("closed_at ="), expr)
        self.assertEqual({"S": NOW}, values[vso._CLOSED_AT_VALUE_KEY])

    def test_it_carries_the_instant_it_is_given(self):
        _e, a = vso.closed_at_set_parts("task", "closed", "2026-01-01T00:00:00Z")
        _e, b = vso.closed_at_set_parts("task", "closed", "2026-12-31T23:59:59Z")
        self.assertNotEqual(a[vso._CLOSED_AT_VALUE_KEY],
                            b[vso._CLOSED_AT_VALUE_KEY])

    def test_non_task_and_non_close_yield_nothing(self):
        for rt, st in (("issue", "closed"), ("feature", "closed"),
                       ("plan", "closed"), ("task", "merged-main"),
                       ("task", "in-progress"), ("", ""), (None, None)):
            expr, values = vso.closed_at_set_parts(rt, st, NOW)
            self.assertEqual("", expr, f"{rt}/{st} must yield no fragment")
            self.assertEqual({}, values)

    def test_inputs_are_normalised_like_the_counter(self):
        for rt, st in (("TASK", "CLOSED"), (" task ", " closed ")):
            expr, _v = vso.closed_at_set_parts(rt, st, NOW)
            self.assertTrue(expr.startswith(", closed_at ="), f"{rt}/{st}")

    def test_value_key_collides_with_nothing_in_the_expression(self):
        other = {":new_status", ":expected_prior", ":ts", ":note", ":zero",
                 ":one", ":vseq", ":fscope", ":vsq_wkind", ":vsq_cc_one"}
        self.assertNotIn(vso._CLOSED_AT_VALUE_KEY, other)


class PredicateParityTests(unittest.TestCase):
    """The date and the count must never disagree about whether a close happened."""

    CASES = [("task", "closed"), ("task", "CLOSED"), ("task", "merged-main"),
             ("issue", "closed"), ("feature", "closed"), ("plan", "closed"),
             ("task", ""), ("", "closed"), (None, "closed"), ("task", None)]

    def test_both_fire_or_neither_does(self):
        for rt, st in self.CASES:
            ca, _cav = vso.closed_at_set_parts(rt, st, NOW)
            cc, _ccv = vso.closed_count_add_parts(rt, st)
            self.assertEqual(
                bool(ca), bool(cc),
                f"{rt!r}/{st!r}: closed_at={bool(ca)} but closed_count={bool(cc)}")


class LadderIndependenceTests(unittest.TestCase):
    """AC-3: the stamp holds under every sequencing source the pinned layer allows.

    version_seq_ops resolves its rule at import time into module-level _rule and
    SEQUENCING_SOURCE. The three reachable states are simulated here by swapping
    _rule, which is exactly what differs between the rungs.
    """

    def setUp(self):
        self._rule = vso._rule
        self._src = vso.SEQUENCING_SOURCE
        self.addCleanup(setattr, vso, "_rule", self._rule)
        self.addCleanup(setattr, vso, "SEQUENCING_SOURCE", self._src)

    def _rungs(self):
        def shared(ddb, table):
            return (", version_seq = :vseq, feed_scope = :fscope, "
                    "write_kind = :vsq_wkind",
                    {":vseq": {"N": "9"}, ":fscope": {"S": "global"},
                     ":vsq_wkind": {"S": "governed"}}, 9)

        def primitives(ddb, table):
            return shared(ddb, table)

        return (("shared_layer_rule", shared),
                ("shared_layer_primitives", primitives),
                ("unavailable", None))

    def test_fragment_is_identical_on_every_rung(self):
        seen = set()
        for source, rule in self._rungs():
            vso._rule, vso.SEQUENCING_SOURCE = rule, source
            expr, values = vso.closed_at_set_parts("task", "closed", NOW)
            seen.add((expr, values[vso._CLOSED_AT_VALUE_KEY]["S"]))
        self.assertEqual(
            1, len(seen),
            "closed_at must not vary with the sequencing source; got " + repr(seen))

    def test_close_is_still_dated_when_sequencing_degrades(self):
        """The ladder's bottom rung stamps write_kind only -- closed_at must survive."""
        vso._rule, vso.SEQUENCING_SOURCE = None, "unavailable"

        class _Ddb:
            def update_item(self, **kw):
                raise AssertionError("no counter call expected on this rung")

        vseq_expr, _vv = vso.sequenced_write_parts(_Ddb(), "t")
        ca_expr, ca_vals = vso.closed_at_set_parts("task", "closed", NOW)
        cc_expr, _cv = vso.closed_count_add_parts("task", "closed")
        update = ("SET #status = :new_status, updated_at = :ts"
                  + vseq_expr + ca_expr + cc_expr)

        self.assertNotIn("version_seq", update, "this rung cannot sequence")
        self.assertIn("write_kind =", update)
        self.assertIn("closed_at =", _set_clause(update))
        self.assertIn("closed_count", _add_clause(update))
        self.assertIsNone(re.search(r" ADD .*=", update), update)
        self.assertEqual({"S": NOW}, ca_vals[vso._CLOSED_AT_VALUE_KEY])


class WriterStructureTests(unittest.TestCase):
    """Both _set_tracker_status copies splice the fragment the same way.

    They are byte-identical in this region by design, and a fix applied to one
    and not the other is the failure this guards: ruling D-24 counts them as two
    of the six close writers precisely because they are separate code.
    """

    FILES = ("lambda_function.py", "tracker_ops.py")

    @classmethod
    def setUpClass(cls):
        here = os.path.dirname(__file__)
        cls.src = {f: open(os.path.join(here, f), encoding="utf-8").read()
                   for f in cls.FILES}

    def test_both_copies_bind_and_splice_the_rule(self):
        for f, s in self.src.items():
            self.assertEqual(
                1, s.count("_ca_expr, _ca_vals = closed_at_set_parts("),
                f"{f} must bind the rule exactly once")
            self.assertIn("+ _vseq_expr + _ca_expr + _cc_expr", s,
                          f"{f}: SET fragments must precede the ADD (ENC-TSK-P49)")
            self.assertIn("_attr_values.update(_ca_vals)", s,
                          f"{f} must bind the value")
            self.assertIn("closed_at_set_parts", s.split("def _set_tracker_status")[0],
                          f"{f} must import the rule")

    def test_neither_copy_drifted_from_the_other(self):
        """The CODE that builds the write must match; the prose around it need not.

        The two copies already differ in comment wording, and that is harmless.
        What must not drift is the expression construction itself -- a fix
        applied to one writer and not the other is the bug this guards.
        """
        def code_only(text):
            body = text.split("def _set_tracker_status", 1)[1]
            body = body[:body.index("try:")]
            return [ln.strip() for ln in body.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")]

        a, b = (code_only(self.src[f]) for f in self.FILES)
        self.assertEqual(a, b,
                         "the two copies' write-building code must stay identical")
        self.assertIn("+ _vseq_expr + _ca_expr + _cc_expr", a)

    def test_the_condition_and_ccfx_contract_are_untouched(self):
        for f, s in self.src.items():
            self.assertIn('ConditionExpression="#status = :expected_prior"', s, f)
            self.assertIn("ConditionalCheckFailedException", s, f)


if __name__ == "__main__":
    unittest.main()
