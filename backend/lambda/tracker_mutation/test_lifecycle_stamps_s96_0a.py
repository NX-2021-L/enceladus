"""ENC-TSK-S96-0A (ENC-PLN-108 W1.1) -- the two lifecycle stamps.

first_checked_out_at is stamped once, by if_not_exists in the checkout
UpdateItem. closed_at is stamped at every close that lands a task at closed,
through the single helper _closed_at_set_parts.

The contract under test is DOC-B8285D689DAC sections 1 and 2. Two of its clauses
are the reason this file exists rather than a pair of smoke tests:

  * closed_at is deliberately ABSENT from _RESERVED_OVERRIDE_PATHS, so an
    io-approved escalation may supply a close time the backfill could not
    establish (ruling D-21). The applier must therefore stamp only when
    field_values is silent -- assigning it from both places would name one
    document path twice, which DynamoDB rejects and _render_update_expression
    raises in-process (ENC-ISS-759).
  * every stamp is a SET assignment and must be spliced BEFORE any ADD clause
    (ENC-TSK-P49, where every governed task close failed on that ordering).

Four of the five close sites build their expression by string concatenation
inside large handlers, so they are fenced structurally here and proved
behaviourally on gamma (DOC-5E1E205FA664 criterion 18). The escalation applier
is callable in isolation, so it is tested for real.
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
    "tracker_mutation_lifecycle_stamps_s96_0a",
    os.path.join(_HERE, "lambda_function.py"),
)
tm = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)


def _set_clause(expr: str) -> str:
    return expr.split(" ADD ", 1)[0]


def _add_clause(expr: str) -> str:
    return expr.split(" ADD ", 1)[1] if " ADD " in expr else ""


class _FakeDdb:
    def __init__(self, start: int = 7700):
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


class ClosedAtRuleTests(unittest.TestCase):
    """The helper is the one place closed_at is spelled."""

    def test_fragment_is_appendable_and_set_only(self):
        expr, values = tm._closed_at_set_parts("2026-11-19T03:00:00Z")
        self.assertTrue(expr.startswith(", "),
                        f"must append onto an existing SET clause: {expr!r}")
        self.assertNotIn(" ADD ", expr, "the rule must never emit an ADD clause")
        self.assertEqual(1, expr.count("closed_at ="))
        self.assertEqual({"S": "2026-11-19T03:00:00Z"},
                         values[tm._CLOSED_AT_VALUE_KEY])

    def test_fragment_carries_the_instant_it_is_given(self):
        _e, a = tm._closed_at_set_parts("2026-01-01T00:00:00Z")
        _e, b = tm._closed_at_set_parts("2026-12-31T23:59:59Z")
        self.assertNotEqual(a[tm._CLOSED_AT_VALUE_KEY],
                            b[tm._CLOSED_AT_VALUE_KEY])

    def test_value_key_is_distinct_from_the_sequencing_keys(self):
        """A collision here would silently overwrite one stamp with the other."""
        self.assertNotIn(tm._CLOSED_AT_VALUE_KEY,
                         {":vseq", ":fscope", ":vsq_wkind", ":now", ":one"})


class ReservedFieldPostureTests(unittest.TestCase):
    """Who may write the stamps, and -- just as load-bearing -- who may not."""

    def test_both_stamps_are_server_side_only(self):
        self.assertEqual({"first_checked_out_at", "closed_at"},
                         set(tm._W11_SERVER_STAMPED_TIMESTAMPS))

    def test_closed_at_stays_out_of_reserved_override_paths(self):
        """Ruling D-21's escalation route depends on this exact absence."""
        self.assertNotIn("closed_at", tm._RESERVED_OVERRIDE_PATHS)

    def test_the_counter_guard_is_untouched(self):
        self.assertEqual({"closed_count", "checkout_count"},
                         set(tm._F41_RESERVED_COUNTER_FIELDS))

    def test_overlap_guard_would_catch_a_double_assignment(self):
        """If the field_values check were ever removed, this is what would fire."""
        with self.assertRaises(ValueError):
            tm._render_update_expression([
                ("closed_at", "closed_at = :a"),
                ("closed_at", "closed_at = :b"),
            ])


class EscalationClosedAtTests(unittest.TestCase):
    """Site 1 of 5, behavioural: the escalated direct_state_override close."""

    def setUp(self):
        self.ddb = _FakeDdb()
        real = tm._get_ddb
        tm._get_ddb = lambda: self.ddb
        self.addCleanup(setattr, tm, "_get_ddb", real)

    def _close(self, record_type="task", field_values=None):
        tm._apply_direct_state_override(
            "enceladus",
            {"item_id": "ENC-ESC-999",
             "payload": {"target_status": "closed",
                         "field_values": field_values or {}}},
            {"item_id": "ENC-TSK-S96-0A", "record_type": record_type,
             "status": "merged-main"},
        )
        writes = self.ddb.record_writes
        self.assertEqual(1, len(writes))
        return writes[0]

    def test_task_close_stamps_closed_at_once(self):
        call = self._close()
        expr = call["UpdateExpression"]
        self.assertEqual(1, expr.count("closed_at ="), expr)
        self.assertIn(tm._CLOSED_AT_VALUE_KEY, call["ExpressionAttributeValues"])

    def test_stamp_sits_in_set_before_the_add(self):
        expr = self._close()["UpdateExpression"]
        self.assertIn("closed_at =", _set_clause(expr))
        self.assertNotIn("closed_at =", _add_clause(expr))
        self.assertIn("closed_count", _add_clause(expr))
        self.assertIsNone(re.search(r" ADD .*=", expr), expr)

    def test_field_values_wins_and_is_not_assigned_twice(self):
        """Ruling D-21: io may supply a close time the backfill could not date.

        The override loop assigns field_values through an ExpressionAttributeNames
        alias (#fv0), so closed_at never appears literally in the expression; the
        collision the ENC-ISS-759 guard would catch is between that alias and the
        helper's own literal assignment. Both halves are checked here.
        """
        call = self._close(field_values={"closed_at": "2020-05-05T05:05:05Z"})
        expr = call["UpdateExpression"]
        names = call["ExpressionAttributeNames"]
        aliased = [k for k, v in names.items() if v == "closed_at"]
        self.assertEqual(1, len(aliased),
                         f"closed_at must be aliased exactly once: {names!r}")
        self.assertIn(f"{aliased[0]} = ", expr)
        self.assertNotIn(
            "closed_at =", expr,
            "the helper must not add a second, literal closed_at assignment")
        self.assertNotIn(
            tm._CLOSED_AT_VALUE_KEY, call["ExpressionAttributeValues"],
            "the helper must not bind its value when field_values supplies one")
        supplied = [v for v in call["ExpressionAttributeValues"].values()
                    if v == {"S": "2020-05-05T05:05:05Z"}]
        self.assertEqual(1, len(supplied), call["ExpressionAttributeValues"])

    def test_non_task_close_carries_no_closed_at(self):
        expr = self._close(record_type="issue")["UpdateExpression"]
        self.assertNotIn("closed_at", expr,
                         "closed_at is defined on tracker.task only")
        self.assertNotIn("closed_count", expr)

    def test_a_non_closing_override_does_not_stamp(self):
        tm._apply_direct_state_override(
            "enceladus",
            {"item_id": "ENC-ESC-998",
             "payload": {"target_status": "in-progress", "field_values": {}}},
            {"item_id": "ENC-TSK-S96-0A", "record_type": "task",
             "status": "open"},
        )
        expr = self.ddb.record_writes[0]["UpdateExpression"]
        self.assertNotIn("closed_at", expr,
                         "only a write that lands status=closed stamps closed_at")


class StampSiteStructureTests(unittest.TestCase):
    """The checkout write and the four concatenated close sites, fenced in source.

    These handlers are not callable in isolation without standing up most of the
    tracker API, so the invariant that actually breaks in production -- a SET
    assignment appended after ' ADD ' -- is asserted on the source text, and the
    behaviour is proved once per site on gamma (criterion 18).
    """

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(_HERE, "lambda_function.py"), encoding="utf-8") as fh:
            cls.src = fh.read()

    def _assert_before(self, earlier, later, why):
        self.assertIn(earlier, self.src, f"missing: {earlier!r}")
        self.assertIn(later, self.src, f"missing: {later!r}")
        self.assertLess(self.src.index(earlier), self.src.index(later), why)

    def test_checkout_stamps_first_checked_out_at_before_the_add(self):
        stamp = ', first_checked_out_at = if_not_exists(first_checked_out_at, :now)'
        self.assertIn(stamp, self.src)
        self._assert_before(
            stamp, 'checkout_update_expr += " ADD checkout_count :one"',
            "the stamp is a SET assignment and must precede the ADD (ENC-TSK-P49)")

    def test_checkout_stamp_is_idempotent_by_construction(self):
        """if_not_exists is what makes a re-checkout leave the first instant alone."""
        self.assertIn("if_not_exists(first_checked_out_at, :now)", self.src)
        self.assertEqual(
            1, self.src.count("first_checked_out_at = if_not_exists"),
            "exactly one site may stamp first_checked_out_at")

    def test_every_close_site_binds_the_one_rule(self):
        self.assertEqual(
            5, self.src.count("= _closed_at_set_parts("),
            "the five tracker_mutation close sites must each bind the helper "
            "exactly once; the 'def' line is excluded by requiring the '= ' form")
        self.assertEqual(1, self.src.count("def _closed_at_set_parts("),
                         "one definition, one place closed_at is spelled")

    def test_arc_walker_splices_the_stamp_into_extra_set(self):
        self.assertIn("_aw_closed_at_pending = False", self.src)
        self._assert_before(
            "_aw_closed_at_pending = False",
            "if _aw_closed_at_pending:",
            "the flag must be initialised before it is read")
        self.assertIn("extra_set += _aw_cl_expr", self.src)
        self.assertIn("+ extra_set + _aw_vseq_expr + add_clause", self.src)

    def test_human_override_stamps_before_sequencing_and_add(self):
        self._assert_before(
            "ui_update_expr += _ui_cl_expr",
            "ui_update_expr += _ui_vseq_expr",
            "the stamp must land inside SET")
        self._assert_before(
            "ui_update_expr += _ui_vseq_expr",
            'ui_update_expr += " ADD closed_count :one"',
            "and everything in SET must precede the ADD")
        self.assertIn("ui_attr_values.update(_ui_cl_vals)", self.src)

    def test_generic_patch_stamps_before_sequencing_and_add(self):
        self._assert_before(
            "update_expr += _patch_cl_expr",
            "update_expr += vseq_expr",
            "the stamp must land inside SET")
        self._assert_before(
            "update_expr += vseq_expr",
            'if _patch_is_task_close:\n        update_expr += " ADD closed_count :one"',
            "and everything in SET must precede the ADD")
        self.assertIn("attr_values.update(_patch_cl_vals)", self.src)

    def test_generic_patch_reuses_one_close_predicate(self):
        """The stamp and the counter must not drift apart on separate conditions."""
        self.assertEqual(3, self.src.count("_patch_is_task_close"),
                         "declared once, then read by the stamp and by the ADD")

    def test_legacy_pwa_close_stamps_before_sequencing_and_add(self):
        self._assert_before(
            "pwa_close_update_expr += _pwa_cl_expr",
            "pwa_close_update_expr += _vseq_expr",
            "the stamp must land inside SET")
        self._assert_before(
            "pwa_close_update_expr += _vseq_expr",
            'pwa_close_update_expr += " ADD closed_count :one"',
            "and everything in SET must precede the ADD")
        self.assertIn("_pwa_close_vals.update(_pwa_cl_vals)", self.src)

    def test_both_stamps_are_refused_from_clients(self):
        self.assertIn("_W11_SERVER_STAMPED_TIMESTAMPS", self.src)
        self.assertEqual(
            3, self.src.count("_W11_SERVER_STAMPED_TIMESTAMPS"),
            "the set, the create-time guard and the PATCH guard")


if __name__ == "__main__":
    unittest.main()
