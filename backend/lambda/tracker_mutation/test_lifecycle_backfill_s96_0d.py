"""ENC-TSK-S96-0D (ENC-PLN-108 W1.4) -- the lifecycle-stamp backfill.

Three layers, each answering one acceptance criterion:

  * ExtractorFixtures      AC-1 and AC-2: the extractor recognises the checkout note and
                           every close note, and NEVER writes a closed_at the history does
                           not prove (D-21); otherwise it yields the closed_at_unknown marker.
  * MarkerWriteRoute       AC-4 and the W1.3 hand-off: the governed route is a marker write,
                           allocates no version_seq, touches the three stamp attributes and
                           write_kind ONLY, and leaves the W1.1 client guard intact.
  * OperatorScript         AC-3 and AC-4: the dry-run report, and a script that holds no
                           table credentials and sends no timestamp.

Writer notes are taken from the writers themselves wherever a writer is callable in
isolation (the escalation applier, the arc-walker history builder); the rest are pinned to
the writer's own source text, so editing a close note without updating the extractor fails
here instead of silently turning proven closes into unknown ones.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import sys
import unittest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

_HERE = os.path.dirname(__file__)
_LAMBDAS = os.path.dirname(_HERE)
_REPO = os.path.dirname(os.path.dirname(_LAMBDAS))
sys.path.insert(0, _HERE)

_spec = importlib.util.spec_from_file_location(
    "tracker_mutation_lifecycle_backfill_s96_0d", os.path.join(_HERE, "lambda_function.py"))
tm = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)

_lbspec = importlib.util.spec_from_file_location(
    "lifecycle_backfill_under_test_s96_0d", os.path.join(_HERE, "lifecycle_backfill.py"))
lb = importlib.util.module_from_spec(_lbspec)
assert _lbspec and _lbspec.loader
_lbspec.loader.exec_module(lb)


def _src(*parts: str) -> str:
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


TM_SRC = _src(_HERE, "lambda_function.py")


def h(desc, ts="2026-05-01T10:00:00Z", status="worklog"):
    return {"description": desc, "status": status, "timestamp": ts}


def task(history, status="closed", **kw):
    rec = {"record_id": "task#ENC-TSK-FIX", "status": status, "history": history,
           "checkout_count": 1, "closed_count": 1}
    rec.update(kw)
    return rec


CHECKOUT = "Agent session checkout by ENC-SES-0TH [provider=ENC-SES-0TH]"
GENERIC_CLOSE = ("Field 'status' set to 'closed' [provider=ENC-SES-0TJ] [evidence: live_validation: "
                 "Gamma v0.1.0+b23a0ba (deploy job 132283112448, which includes d0f9bdd4 via job 1]")
HUMAN_CLOSE = "[USER-INITIATED] Status changed to 'closed' by me@example.com. Note: shipped"
COORD_CLOSE = "Coordination request CRQ-ABC123 completed successfully."


def _real_escalation_close_entry():
    """The history entry the REAL escalation applier writes for a task close."""
    calls = []

    class Ddb:
        def update_item(self, **kw):
            calls.append(kw)
            return {}

    real = tm._get_ddb
    tm._get_ddb = lambda: Ddb()
    try:
        tm._apply_direct_state_override(
            "enceladus",
            {"item_id": "ENC-ESC-901", "mutation_type": "direct_state_override",
             "requested_by": {"session_id": "ENC-SES-0XO"},
             "approved_by": {"email": "io@example.com"},
             "payload": {"target_status": "closed", "field_values": {}}},
            {"item_id": "ENC-TSK-FIX", "record_type": "task", "status": "merged-main"},
        )
    finally:
        tm._get_ddb = real
    write = next(c for c in calls if ":hentry" in c["ExpressionAttributeValues"])
    entry = tm._deser_val(write["ExpressionAttributeValues"][":hentry"])[0]
    return dict(entry, timestamp="2026-06-01T12:00:00Z")


def _real_arc_walker_close_entry():
    entry = tm._deser_val(tm._arc_walk_history_entry(
        "2026-06-02T12:00:00Z", "deploy-success", "closed", "MECHANICAL",
        "code_only|closed reuses commit_sha abc", 1))
    return entry


def _real_arc_walker_nonclose_entry():
    return tm._deser_val(tm._arc_walk_history_entry(
        "2026-06-02T11:00:00Z", "pr", "merged-main", "MECHANICAL", "x", 1))


# ---------------------------------------------------------------------------
# AC-1 / AC-2
# ---------------------------------------------------------------------------

class CheckoutNoteTests(unittest.TestCase):
    def test_first_checkout_note_is_recognised_with_provider_suffix(self):
        rec = task([h("Created via tracker API: x", status="created"),
                    h(CHECKOUT, "2026-05-01T01:00:00Z")])
        self.assertEqual(("2026-05-01T01:00:00Z", 1, "found"), lb.first_checkout(rec))

    def test_the_FIRST_checkout_wins_not_the_latest(self):
        rec = task([h(CHECKOUT, "2026-05-01T01:00:00Z"),
                    h("Agent session checkout by ENC-SES-0TJ [provider=ENC-SES-0TJ]", "2026-05-09T01:00:00Z")])
        self.assertEqual("2026-05-01T01:00:00Z", lb.first_checkout(rec)[0])

    def test_checkout_note_must_be_anchored(self):
        rec = task([h("see: Agent session checkout by ENC-SES-0TH")])
        self.assertEqual("none", lb.first_checkout(rec)[2])

    def test_unparsable_first_checkout_is_not_replaced_by_a_later_one(self):
        rec = task([h(CHECKOUT, "garbage"), h(CHECKOUT, "2026-05-09T01:00:00Z")])
        self.assertEqual((None, 0, "unparsable_timestamp"), lb.first_checkout(rec))

    def test_checkout_note_matches_the_writer_source(self):
        self.assertIn('f"Agent session checkout by {agent_id}{note_suffix}"', TM_SRC)


class CloseNoteRecognitionTests(unittest.TestCase):
    """One fixture per close writer. Each must be proven, by the right writer."""

    def _proven(self, entry, writer, ts):
        d = lb.derive_closed_at(task([h(CHECKOUT), entry]))
        self.assertEqual("proven", d["state"], d)
        self.assertEqual(writer, d["writer"])
        self.assertEqual(ts, d["closed_at"])

    def test_1_generic_patch_behind_checkout_advance(self):
        self._proven(h(GENERIC_CLOSE, "2026-05-02T00:00:00Z"),
                     "tracker_mutation.generic_patch", "2026-05-02T00:00:00Z")

    def test_1b_generic_patch_without_suffix(self):
        self._proven(h("Field 'status' set to 'closed'", "2026-05-02T00:00:00Z"),
                     "tracker_mutation.generic_patch", "2026-05-02T00:00:00Z")

    def test_2_legacy_pwa_close(self):
        self._proven(h("Closed via Enceladus PWA", "2026-05-03T00:00:00Z", status="close_audit"),
                     "tracker_mutation.pwa_close", "2026-05-03T00:00:00Z")

    def test_3_escalation_direct_state_override_REAL_APPLIER_OUTPUT(self):
        entry = _real_escalation_close_entry()
        self.assertTrue(entry["description"].startswith("[ESCALATION-APPLIED]"))
        self._proven(entry, "tracker_mutation.escalation_override", "2026-06-01T12:00:00Z")

    def test_4_arc_walker_code_only_close_REAL_BUILDER_OUTPUT(self):
        self._proven(_real_arc_walker_close_entry(),
                     "tracker_mutation.arc_walker", "2026-06-02T12:00:00Z")

    def test_5_human_override_advance(self):
        self._proven(h(HUMAN_CLOSE, "2026-05-05T00:00:00Z"),
                     "tracker_mutation.human_override", "2026-05-05T00:00:00Z")

    def test_6_and_7_coordination_set_tracker_status_both_copies_share_one_note(self):
        self._proven(h(COORD_CLOSE, "2026-05-06T00:00:00Z"),
                     "coordination_api._set_tracker_status", "2026-05-06T00:00:00Z")

    def test_retired_bedrock_writer_quoted_and_unquoted_are_history_only_closes(self):
        for note in ("Status changed to 'closed' by bedrock agent",
                     "Status changed to closed by bedrock agent"):
            self._proven(h(note, "2026-05-07T00:00:00Z"),
                         "bedrock_agent_actions._handle_tracker_status", "2026-05-07T00:00:00Z")

    def test_every_close_writer_in_the_table_has_a_recognition_test_above(self):
        self.assertEqual(
            {"tracker_mutation.generic_patch", "tracker_mutation.pwa_close",
             "tracker_mutation.escalation_override", "tracker_mutation.arc_walker",
             "tracker_mutation.human_override", "coordination_api._set_tracker_status"},
            set(lb.CLOSE_WRITERS))
        self.assertEqual({"bedrock_agent_actions._handle_tracker_status"}, set(lb.RETIRED_CLOSE_WRITERS))

    def test_seven_close_sites_are_covered(self):
        """Five tracker_mutation sites + the two coordination_api _set_tracker_status copies = seven."""
        self.assertEqual(7, sum(len(w["sites"]) for w in lb.CLOSE_WRITERS.values()))

    def test_a_non_closing_escalation_or_walk_is_not_a_close(self):
        t = lb.parse_status_write(_real_arc_walker_nonclose_entry())
        self.assertEqual(("tracker_mutation.arc_walker", "merged-main"), (t.writer, t.to_status))
        deploy_arc = h("[ESCALATION-APPLIED] ENC-ESC-1 (deploy_arc_change) requested_by=x approved_by=io "
                       'before={"transition_type": "a"} after={"transition_type": "b"} waived=[]')
        self.assertIsNone(lb.parse_status_write(deploy_arc))


class WriterSourcePinTests(unittest.TestCase):
    """The skeletons are extracted from the writers' own format strings; pin them."""

    def test_tracker_mutation_skeletons(self):
        for literal in (
            "f\"Field '{field}' set to '{note_val}'{note_suffix}\"",
            'description = "Closed via Enceladus PWA"',
            "f\"[USER-INITIATED] Status changed to '{new_lower}' by {cognito_user}. \"",
            'f"[ARC-WALKER][AUTO-ADVANCE] {from_status or \'?\'} -> {to_status} "',
            'f"[ESCALATION-APPLIED] {escalation.get(\'item_id\')} "',
        ):
            self.assertIn(literal, TM_SRC, literal)

    def test_both_coordination_close_callers_emit_the_same_note(self):
        for name in ("lambda_function.py", "lifecycle.py"):
            text = _src(_LAMBDAS, "coordination_api", name)
            self.assertIn('f"Coordination request {rid} completed successfully."', text, name)
        for name in ("lambda_function.py", "tracker_ops.py"):
            text = _src(_LAMBDAS, "coordination_api", name)
            self.assertIn("def _set_tracker_status(", text, name)

    def test_the_bedrock_writer_is_gone_from_the_tree(self):
        text = _src(_LAMBDAS, "bedrock_agent_actions", "lambda_function.py")
        self.assertNotIn("by bedrock agent", text,
                         "if this reappears the writer is live again and needs a closed_at stamp (D-24)")


class NeverGuessTests(unittest.TestCase):
    """AC-2: no closed_at unless the history proves it; otherwise the explicit marker."""

    def _plan(self, history, **kw):
        return lb.plan_lifecycle_stamps(task(history, **kw))

    def test_closed_with_no_close_note_is_unknown_and_has_no_closed_at(self):
        p = self._plan([h(CHECKOUT), h("Field 'status' set to 'in-progress'")],
                       updated_at="2026-09-09T09:09:09Z")
        self.assertEqual("unknown", p["close_class"])
        self.assertNotIn("closed_at", p["set"])
        self.assertEqual("no_recognised_close_note", p["set"]["closed_at_unknown"]["reason"])

    def test_updated_at_is_never_used_as_a_fallback(self):
        """The mart falls back to updated_at; D-21 forbids exactly that inference."""
        p = self._plan([], updated_at="2026-09-09T09:09:09Z", created_at="2026-01-01T00:00:00Z")
        self.assertNotIn("closed_at", p["set"])
        self.assertNotIn("2026-09-09", json.dumps(p))

    def test_empty_or_missing_history_is_unknown(self):
        for hist in ([], None):
            rec = task([])
            rec["history"] = hist
            p = lb.plan_lifecycle_stamps(rec)
            self.assertEqual("unknown", p["close_class"])
            self.assertNotIn("closed_at", p["set"])

    def test_prose_that_merely_quotes_a_note_is_not_proof(self):
        """The mart's unanchored search would accept this; an anchored match must not."""
        p = self._plan([h("Reviewer note: the PR text says Field 'status' set to 'closed' but it was not")])
        self.assertEqual("unknown", p["close_class"])
        self.assertNotIn("closed_at", p["set"])

    def test_unparsable_close_timestamp_is_unknown(self):
        p = self._plan([h(GENERIC_CLOSE, "yesterday")])
        self.assertEqual("close_note_timestamp_unparsable", p["unknown_reason"])
        self.assertNotIn("closed_at", p["set"])

    def test_a_timestamp_without_a_zone_is_refused_not_assumed_utc(self):
        p = self._plan([h(GENERIC_CLOSE, "2026-05-02T00:00:00")])
        self.assertEqual("unknown", p["close_class"])

    def test_close_by_an_unrecognised_writer_is_unknown(self):
        p = self._plan([h("Status changed to 'closed'", "2026-05-02T00:00:00Z")])
        self.assertEqual("close_by_unrecognised_writer", p["unknown_reason"])
        p = self._plan([h("totally different text", "2026-05-02T00:00:00Z", status="closed")])
        self.assertEqual("close_by_unrecognised_writer", p["unknown_reason"])

    def test_an_unrecognised_status_write_AFTER_the_last_close_blocks_the_proof(self):
        p = self._plan([h(GENERIC_CLOSE, "2026-05-02T00:00:00Z"),
                        h("Status changed to 'closed'", "2026-06-02T00:00:00Z")])
        self.assertEqual("later_unrecognised_status_write", p["unknown_reason"])
        self.assertNotIn("closed_at", p["set"])

    def test_reopened_after_the_last_close_but_closed_now_is_unknown(self):
        p = self._plan([h(GENERIC_CLOSE, "2026-05-02T00:00:00Z"),
                        h("Field 'status' set to 'coding-updates' [provider=x]", "2026-05-03T00:00:00Z")])
        self.assertEqual("reopened_after_last_close", p["unknown_reason"])
        self.assertNotIn("closed_at", p["set"])

    def test_pwa_reopen_after_close_is_unknown(self):
        p = self._plan([h("Closed via Enceladus PWA", "2026-05-02T00:00:00Z", status="close_audit"),
                        h("Reopened via Enceladus PWA", "2026-05-03T00:00:00Z", status="reopened")])
        self.assertEqual("reopened_after_last_close", p["unknown_reason"])

    def test_reopen_then_reclose_proves_the_LAST_close(self):
        p = self._plan([h(GENERIC_CLOSE, "2026-05-02T00:00:00Z"),
                        h("Field 'status' set to 'coding-updates' [provider=x]", "2026-05-03T00:00:00Z"),
                        h("Field 'status' set to 'committed' [provider=x]", "2026-05-04T00:00:00Z"),
                        h(HUMAN_CLOSE, "2026-05-05T00:00:00Z"),
                        h("Agent session released", "2026-05-05T00:00:01Z")])
        self.assertEqual("proven", p["close_class"])
        self.assertEqual("2026-05-05T00:00:00Z", p["set"]["closed_at"])
        self.assertEqual("tracker_mutation.human_override", p["close_writer"])
        self.assertNotIn("closed_at_unknown", p["set"])

    def test_a_task_that_is_not_closed_is_never_dated(self):
        p = self._plan([h(GENERIC_CLOSE)], status="in-progress")
        self.assertEqual("not_closed", p["close_class"])
        self.assertNotIn("closed_at", p["set"])
        self.assertNotIn("closed_at_unknown", p["set"])

    def test_existing_values_are_never_replaced(self):
        p = self._plan([h(CHECKOUT, "2026-05-01T00:00:00Z"), h(GENERIC_CLOSE, "2026-05-02T00:00:00Z")],
                       closed_at="2099-01-01T00:00:00Z", first_checked_out_at="2099-01-01T00:00:00Z")
        self.assertEqual({}, p["set"])
        self.assertEqual("already_set", p["close_class"])
        self.assertEqual("already_set", p["checkout_class"])

    def test_a_proof_never_overwrites_an_existing_unknown_marker(self):
        p = self._plan([h(GENERIC_CLOSE, "2026-05-02T00:00:00Z")], closed_at_unknown={"reason": "x"})
        self.assertEqual("proven_but_unknown_marker_present", p["close_class"])
        self.assertNotIn("closed_at", p["set"])

    def test_timestamps_are_normalised_to_utc_seconds(self):
        self.assertEqual("2026-05-02T00:00:00Z", lb.normalise_timestamp("2026-05-02T00:00:00.123456Z"))
        self.assertEqual("2026-05-02T00:00:00Z", lb.normalise_timestamp("2026-05-02T05:30:00+05:30"))
        self.assertIsNone(lb.normalise_timestamp("2026-13-45T00:00:00Z"))
        self.assertIsNone(lb.normalise_timestamp(None))

    def test_the_marker_explains_itself(self):
        m = lb.marker_value({"reason": "no_recognised_close_note", "detail": "d"}, "run-1", "2026-11-19T10:00:00Z")
        self.assertEqual({"reason", "detail", "basis", "backfill_run_id", "recorded_at", "extractor_version"}, set(m))
        self.assertIn("D-21", m["basis"])


class CheckoutCountTests(unittest.TestCase):
    """first_checked_out_at follows checkout_count (criterion 17)."""

    def test_count_zero_gets_no_stamp(self):
        p = lb.plan_lifecycle_stamps(task([h("Field 'status' set to 'closed'")], checkout_count=0))
        self.assertEqual("never_checked_out", p["checkout_class"])
        self.assertNotIn("first_checked_out_at", p["set"])
        self.assertFalse(p["checked_out"])

    def test_missing_count_is_treated_as_zero(self):
        rec = task([]); del rec["checkout_count"]
        self.assertFalse(lb.plan_lifecycle_stamps(rec)["checked_out"])

    def test_count_zero_with_a_checkout_note_is_stamped_and_still_flagged(self):
        """io ruling D-31 (2026-11-19): history wins; checkout_count is corroboration.

        This test previously asserted the opposite -- that a zero count suppressed the
        stamp. The first gamma dry run found 782 real tasks in exactly this shape,
        because checkout_count arrived with ENC-TSK-F41 and was never backfilled, so a
        zero count on a pre-F41 record is an ABSENT counter rather than a claim that no
        checkout happened. Suppressing the stamp discarded proof the extractor held.
        The disagreement is still flagged, so the audit trail survives the ruling.
        """
        p = lb.plan_lifecycle_stamps(task([h(CHECKOUT)], checkout_count=0))
        self.assertIn("first_checked_out_at", p["set"])
        self.assertEqual("stamped", p["checkout_class"])
        self.assertIn("checkout_note_but_count_zero", p["flags"])

    def test_count_zero_with_no_checkout_note_is_still_unstamped(self):
        """D-31 widens what counts as proof; it does not weaken D-21's no-guessing rule."""
        p = lb.plan_lifecycle_stamps(task([h("something else")], checkout_count=0))
        self.assertNotIn("first_checked_out_at", p["set"])
        self.assertEqual("never_checked_out", p["checkout_class"])

    def test_positive_count_without_a_note_is_unprovable_and_flagged(self):
        p = lb.plan_lifecycle_stamps(task([h("x")], checkout_count=2))
        self.assertEqual("checked_out_unprovable", p["checkout_class"])
        self.assertIn("checkout_count_positive_but_no_checkout_note", p["flags"])
        self.assertNotIn("first_checked_out_at", p["set"])

    def test_positive_count_with_a_note_is_stamped(self):
        p = lb.plan_lifecycle_stamps(task([h(CHECKOUT, "2026-05-01T01:00:00Z")], checkout_count=2, status="open"))
        self.assertEqual({"first_checked_out_at": "2026-05-01T01:00:00Z"}, p["set"])


# ---------------------------------------------------------------------------
# AC-4 (route half) and the W1.3 hand-off
# ---------------------------------------------------------------------------

class _FakeDdb:
    def __init__(self):
        self.calls = []
        self.fail_condition = False

    def update_item(self, **kw):
        self.calls.append(kw)
        if self.fail_condition:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "x"}}, "UpdateItem")
        return {}

    def get_item(self, **kw):  # pragma: no cover - the route reads through _get_record_raw
        raise AssertionError("route must read through _get_record_raw")


def _raw(plain):
    return {k: tm._ser_value(v) for k, v in plain.items()}


def _assigned(expr):
    return re.findall(r"(?:^SET |, )([A-Za-z_][A-Za-z0-9_]*) = ", expr)


def _consumer_projection_only(name):
    tree = ast.parse(_src(_LAMBDAS, name, "lambda_function.py"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "PROJECTION_ONLY_ATTRS" for t in node.targets):
            return {n.value for n in ast.walk(node.value) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    raise AssertionError(f"{name}: PROJECTION_ONLY_ATTRS not found")


CLOSED_TASK = task(
    [h(CHECKOUT, "2026-05-01T01:00:00Z"), h(GENERIC_CLOSE, "2026-05-02T00:00:00Z")],
    updated_at="2026-05-02T00:00:00Z", sync_version=7, checkout_count=1)
UNKNOWN_TASK = task([h("Field 'status' set to 'in-progress'")], updated_at="2026-05-02T00:00:00Z",
                    sync_version=3, checkout_count=0)


class MarkerWriteRoute(unittest.TestCase):
    CLAIMS = {"auth_mode": "internal-key"}

    def setUp(self):
        self.ddb = _FakeDdb()
        self.record = dict(CLOSED_TASK)
        for name, val in (("_get_ddb", lambda: self.ddb),
                          ("_get_record_raw", lambda p, t, r: _raw(self.record) if self.record else None)):
            real = getattr(tm, name)
            setattr(tm, name, val)
            self.addCleanup(setattr, tm, name, real)

    def _call(self, body=None, claims=None, record_type="task"):
        resp = tm._handle_lifecycle_backfill(
            "enceladus", record_type, "ENC-TSK-FIX", {"backfill_run_id": "run-1"} if body is None else body,
            self.CLAIMS if claims is None else claims)
        return resp["statusCode"], json.loads(resp["body"])

    @staticmethod
    def _code(body):
        return (body.get("error_envelope") or {}).get("code")

    # ---- what the write is -------------------------------------------------
    def test_writes_a_marker_with_no_version_seq_and_exactly_the_stamp_attributes(self):
        code, body = self._call()
        self.assertEqual(200, code, body)
        self.assertEqual("written", body["outcome"])
        self.assertEqual(1, len(self.ddb.calls), "one UpdateItem: no counter allocation, no audit item")
        call = self.ddb.calls[0]
        expr = call["UpdateExpression"]
        self.assertEqual({"write_kind", "first_checked_out_at", "closed_at"}, set(_assigned(expr)), expr)
        self.assertEqual({"S": "marker"}, call["ExpressionAttributeValues"][":lbf_wk"])
        self.assertFalse(body["version_seq_allocated"])
        for forbidden in ("version_seq", "feed_scope", "updated_at =", "sync_version =", "history",
                          "last_update_note", "write_source", " ADD ", "closed_count", "checkout_count"):
            self.assertNotIn(forbidden, expr, forbidden)
        self.assertNotIn(":vseq", call["ExpressionAttributeValues"])

    def test_every_stamp_is_set_if_absent(self):
        expr = self.ddb.calls[0]["UpdateExpression"] if self._call()[0] == 200 else ""
        self.assertIn("first_checked_out_at = if_not_exists(first_checked_out_at, :lbf_fco)", expr)
        self.assertIn("closed_at = if_not_exists(closed_at, :lbf_cat)", expr)
        vals = self.ddb.calls[0]["ExpressionAttributeValues"]
        self.assertEqual({"S": "2026-05-01T01:00:00Z"}, vals[":lbf_fco"])
        self.assertEqual({"S": "2026-05-02T00:00:00Z"}, vals[":lbf_cat"])

    def test_unknown_marker_write_carries_no_closed_at(self):
        self.record = dict(UNKNOWN_TASK)
        code, body = self._call()
        self.assertEqual(200, code, body)
        expr = self.ddb.calls[0]["UpdateExpression"]
        self.assertEqual({"write_kind", "closed_at_unknown"}, set(_assigned(expr)), expr)
        self.assertIn("closed_at_unknown = if_not_exists(closed_at_unknown, :lbf_cau)", expr)
        marker = tm._deser_val(self.ddb.calls[0]["ExpressionAttributeValues"][":lbf_cau"])
        self.assertEqual("no_recognised_close_note", marker["reason"])
        self.assertEqual("run-1", marker["backfill_run_id"])
        self.assertNotIn(":lbf_cat", self.ddb.calls[0]["ExpressionAttributeValues"])

    def test_the_write_is_guarded_against_a_concurrent_governed_write(self):
        self._call()
        cond = self.ddb.calls[0]["ConditionExpression"]
        for part in ("attribute_exists(record_id)", "#lbf_st = :lbf_seen_st",
                     "updated_at = :lbf_seen_upd", "sync_version = :lbf_seen_sv"):
            self.assertIn(part, cond)

    def test_a_lost_race_writes_nothing_and_is_retryable(self):
        self.ddb.fail_condition = True
        code, body = self._call()
        self.assertEqual((409, "RECORD_CHANGED"), (code, self._code(body)))
        self.assertTrue(body["error_envelope"]["retryable"])

    def test_nothing_to_set_makes_no_write_at_all(self):
        self.record = dict(CLOSED_TASK, closed_at="2026-05-02T00:00:00Z",
                           first_checked_out_at="2026-05-01T01:00:00Z")
        code, body = self._call()
        self.assertEqual((200, "noop"), (code, body["outcome"]))
        self.assertEqual([], self.ddb.calls, "not even a write_kind flip: that would still wake a consumer")

    def test_dry_run_on_the_route_writes_nothing(self):
        code, body = self._call({"backfill_run_id": "run-1", "dry_run": True})
        self.assertEqual((200, "dry_run"), (code, body["outcome"]))
        self.assertEqual([], self.ddb.calls)

    # ---- consumer neutrality (W1.3 hand-off, kill criterion 2) --------------
    def test_everything_the_route_touches_is_projection_only_in_all_three_consumers(self):
        """The stream diff of a backfill write must be a SUBSET of each consumer's guard set."""
        touched = {"write_kind"} | set(tm._LBF_MARKER_ATTRS)
        for name in ("opensearch_indexer", "governance_audit", "convergence_telemetry"):
            guard = _consumer_projection_only(name)
            self.assertLessEqual(touched, guard, f"{name} would re-process every backfilled record")
        for rec in (CLOSED_TASK, UNKNOWN_TASK):
            self.record = dict(rec)
            self.ddb.calls.clear()
            self._call()
            written = set(_assigned(self.ddb.calls[0]["UpdateExpression"]))
            for name in ("opensearch_indexer", "governance_audit", "convergence_telemetry"):
                self.assertLessEqual(written, _consumer_projection_only(name), name)

    def test_the_marker_attr_list_is_exactly_the_three_w1_3_names(self):
        self.assertEqual(("first_checked_out_at", "closed_at", "closed_at_unknown"), tm._LBF_MARKER_ATTRS)

    # ---- the W1.1 client guard stays intact ---------------------------------
    def test_the_route_accepts_no_timestamp_from_the_client(self):
        for attr in tm._LBF_MARKER_ATTRS:
            code, body = self._call({"backfill_run_id": "run-1", attr: "2020-01-01T00:00:00Z"})
            self.assertEqual((400, "RESERVED_FIELD"), (code, self._code(body)), attr)
        self.assertEqual([], self.ddb.calls)

    def test_the_w1_1_create_and_patch_guard_is_untouched(self):
        self.assertEqual({"first_checked_out_at", "closed_at"}, set(tm._W11_SERVER_STAMPED_TIMESTAMPS))
        self.assertNotIn("closed_at", tm._RESERVED_OVERRIDE_PATHS)  # D-21 escalation route stays open
        resp = tm._handle_update_field("enceladus", "task", "ENC-TSK-FIX",
                                       {"field": "closed_at", "value": "2020-01-01T00:00:00Z"})
        self.assertEqual(400, resp["statusCode"])
        self.assertEqual("RESERVED_FIELD", json.loads(resp["body"])["error_envelope"]["code"])
        self.assertEqual([], self.ddb.calls)

    def test_unknown_body_keys_are_refused(self):
        code, _ = self._call({"backfill_run_id": "run-1", "status": "closed"})
        self.assertEqual(400, code)

    # ---- who and what ---------------------------------------------------------
    def test_a_cognito_session_is_refused(self):
        code, _ = self._call(claims={"sub": "someone", "email": "x@y.z"})
        self.assertEqual(403, code)
        self.assertEqual([], self.ddb.calls)

    def test_run_id_is_required(self):
        self.assertEqual(400, self._call({})[0])
        self.assertEqual(400, self._call({"backfill_run_id": "bad id!"})[0])

    def test_tasks_only(self):
        self.assertEqual(400, self._call(record_type="issue")[0])

    def test_missing_record_is_404(self):
        self.record = None
        self.assertEqual(404, self._call()[0])

    def test_the_route_is_wired_and_needs_the_backfill_scope(self):
        path = "/api/v1/tracker/enceladus/task/ENC-TSK-FIX/lifecycle-backfill"
        self.assertTrue(tm._RE_RECORD_SUB.match(path))
        self.assertEqual("tracker.lifecycle_backfill", tm._wa_tool_for("POST", path)[0])
        scopes = []
        reals = {n: getattr(tm, n) for n in ("_authenticate", "_validate_project_exists", "_handle_lifecycle_backfill")}
        tm._authenticate = lambda event, s=None: (scopes.append(s) or ({"auth_mode": "internal-key"}, None))
        tm._validate_project_exists = lambda p: None
        tm._handle_lifecycle_backfill = lambda *a: {"statusCode": 200, "headers": {}, "body": "{}"}
        try:
            resp = tm._lambda_handler_inner({"httpMethod": "POST", "rawPath": path, "body": "{}"}, None)
        finally:
            for n, v in reals.items():
                setattr(tm, n, v)
        self.assertEqual(200, resp["statusCode"])
        self.assertEqual([["tracker:write", "tracker:backfill"]], scopes)

    def test_the_lambda_is_packaged_with_the_extractor(self):
        manifest = json.loads(_src(_REPO, "infrastructure", "lambda_workflow_manifest.json"))
        fns = manifest["functions"] if isinstance(manifest, dict) and "functions" in manifest else manifest
        entry = next(f for f in fns if f.get("function_name") == "devops-tracker-mutation-api")
        self.assertIn("lifecycle_backfill.py", entry["package_extra_files"])


# ---------------------------------------------------------------------------
# AC-3 / AC-4 (script half)
# ---------------------------------------------------------------------------

_sspec = importlib.util.spec_from_file_location(
    "backfill_task_lifecycle_stamps_under_test", os.path.join(_REPO, "tools", "backfill_task_lifecycle_stamps.py"))
script = importlib.util.module_from_spec(_sspec)
assert _sspec and _sspec.loader
_sspec.loader.exec_module(script)


def _pop():
    """A small population covering every bucket of the dry-run report."""
    return [
        # checked out, proven close
        task([h(CHECKOUT, "2026-05-01T01:00:00Z"), h(GENERIC_CLOSE, "2026-05-02T00:00:00Z")], record_id="task#A1"),
        task([h(CHECKOUT, "2026-05-01T01:00:00Z"), h(HUMAN_CLOSE, "2026-05-02T00:00:00Z")], record_id="task#A2"),
        # checked out, unknown close
        task([h(CHECKOUT, "2026-05-01T01:00:00Z")], record_id="task#A3"),
        # never checked out, proven close (closed by coordination, no checkout)
        task([h(COORD_CLOSE, "2026-05-03T00:00:00Z")], record_id="task#B1", checkout_count=0),
        # never checked out, unknown close
        task([], record_id="task#B2", checkout_count=0),
        task([], record_id="task#B3", checkout_count=0, status="open"),
        # checked out, nothing provable about the checkout
        task([h(GENERIC_CLOSE, "2026-05-02T00:00:00Z")], record_id="task#C1", checkout_count=3),
        # count zero but a checkout note (discrepancy)
        task([h(CHECKOUT), h(GENERIC_CLOSE, "2026-05-02T00:00:00Z")], record_id="task#C2", checkout_count=0),
        # already dated
        task([h(CHECKOUT), h(GENERIC_CLOSE)], record_id="task#D1", closed_at="x", first_checked_out_at="y"),
    ]


class FakeClient:
    def __init__(self, tasks, page=4):
        self.tasks, self.page, self.requests = tasks, page, []

    def request(self, method, path, payload=None, query=None):
        self.requests.append((method, path, payload, query))
        if method == "GET":
            start = int((query or {}).get("next_cursor") or 0)
            chunk = self.tasks[start:start + self.page]
            body = {"success": True, "records": chunk, "count": len(chunk)}
            if start + self.page < len(self.tasks):
                body["next_cursor"] = str(start + self.page)
            return 200, body
        return 200, {"success": True, "outcome": "written"}


class OperatorScript(unittest.TestCase):
    def test_report_splits_proven_and_unknown_by_checked_out_and_never_checked_out(self):
        r = script.summarise(_pop())
        self.assertEqual(9, r["tasks_scanned"])
        c = r["close"]
        # checked out: A1, A2 proven; A3 unknown (no close note) ; C1 proven ; C2 is count-zero
        self.assertEqual((3, 1), (c["checked_out"]["proven"], c["checked_out"]["unknown"]))
        # never checked out: B1 proven (coordination), C2 proven (count 0 + note), B2 unknown, B3 not closed
        self.assertEqual((2, 1), (c["never_checked_out"]["proven"], c["never_checked_out"]["unknown"]))
        self.assertEqual(4, r["never_checked_out"])
        self.assertEqual(4, r["checkout_count_zero"])
        self.assertEqual(1, c["checked_out"]["already_set"])
        self.assertEqual({"no_recognised_close_note": 1}, r["unknown_reasons"]["checked_out"])

    def test_report_text_carries_every_required_section(self):
        text = script.render_report(script.summarise(_pop()))
        for needle in ("DRY RUN", "close time PROVEN", "close time UNKNOWN", "checked-out", "never-checked-out",
                       "checkout_count = 0", "Criterion 17", "checkout_note_but_count_zero",
                       "checkout_count_positive_but_no_checkout_note", "Writes planned"):
            self.assertIn(needle, text)

    def test_criterion_17_is_reported_honestly(self):
        """Under io's ruling D-31 the equality is restated, so what breaks it changed.

        It used to break on a zero checkout_count beside a checkout note -- the shape of
        782 real gamma tasks -- which D-31 now stamps from history. The only remaining
        way to hold a checkout note and no stamp is an UNPARSABLE timestamp on that note,
        so that is what must flip 'holds' to false. The baseline population now holds.
        """
        base = script.summarise(_pop())
        self.assertTrue(script.criterion_17(base)["holds"])
        # The 782-shaped task is present in _pop (task#C2) and is now stamped, recorded
        # as an audit figure rather than an exception.
        self.assertEqual(1, script.criterion_17(base)["count_zero_but_stamped_from_history"])

        broken = _pop() + [task([h(CHECKOUT, "not-a-timestamp")], record_id="task#E1")]
        c17 = script.criterion_17(script.summarise(broken))
        self.assertFalse(c17["holds"])
        self.assertEqual(1, c17["note_present_but_unstamped"])
        self.assertEqual(["task#E1"], c17["note_present_but_unstamped_ids"])

    def test_pagination_walks_every_page_and_strips_the_sk_prefix(self):
        client = FakeClient(_pop(), page=4)
        got = list(script.fetch_tasks(client, "enceladus", page_size=4))
        self.assertEqual(9, len(got))
        self.assertEqual("A1", got[0]["record_id"])
        gets = [r for r in client.requests if r[0] == "GET"]
        self.assertEqual(3, len(gets))
        self.assertEqual("task", gets[0][3]["type"])
        self.assertIn("history", gets[0][3]["fields"])

    def test_a_failed_page_aborts_rather_than_undercounting(self):
        class Bad(FakeClient):
            def request(self, *a, **k):
                return 500, {"error": "boom"}
        with self.assertRaises(RuntimeError):
            list(script.fetch_tasks(Bad([]), "enceladus"))

    def test_dry_run_issues_no_write(self):
        client = FakeClient(_pop())
        rc = script.main(["--env", "gamma", "--project", "enceladus", "--dry-run"], client=client)
        self.assertEqual(0, rc)
        self.assertEqual([], [r for r in client.requests if r[0] != "GET"])

    def test_default_mode_is_dry_run(self):
        client = FakeClient(_pop())
        script.main(["--env", "gamma", "--project", "enceladus"], client=client)
        self.assertEqual([], [r for r in client.requests if r[0] != "GET"])

    def test_apply_posts_only_to_the_governed_route_and_never_sends_a_timestamp(self):
        client = FakeClient(_pop())
        rc = script.main(["--env", "gamma", "--project", "enceladus", "--apply", "--run-id", "run-9",
                          "--max-rps", "0"], client=client)
        self.assertEqual(0, rc)
        posts = [r for r in client.requests if r[0] == "POST"]
        self.assertGreater(len(posts), 0)
        for _m, path, payload, _q in posts:
            self.assertRegex(path, r"^/enceladus/task/[A-Z0-9]+/lifecycle-backfill$")
            self.assertEqual({"backfill_run_id": "run-9"}, payload)
        ids = {p[1].split("/")[3] for p in posts}
        self.assertNotIn("D1", ids, "an already-dated task needs no write")
        self.assertNotIn("B3", ids, "a task that is not closed and never checked out needs no write")

    def test_prod_apply_requires_the_preconditions_flag(self):
        client = FakeClient(_pop())
        rc = script.main(["--env", "prod", "--project", "enceladus", "--apply"], client=client)
        self.assertEqual(2, rc)
        self.assertEqual([], client.requests)

    def test_apply_aborts_after_consecutive_failures(self):
        class Fail(FakeClient):
            def request(self, method, path, payload=None, query=None):
                if method == "GET":
                    return super().request(method, path, payload, query)
                return 400, {"error": "no"}
        out = script.apply_writes(Fail([]), "enceladus", [f"T{i}" for i in range(20)], "r",
                                  max_rps=0, sleep=lambda s: None)
        self.assertIn("aborted", out)
        self.assertLess(out["failed"], 20)

    def test_a_lost_race_is_retried_using_the_real_error_envelope_shape(self):
        class Flaky(FakeClient):
            n = 0

            def request(self, method, path, payload=None, query=None):
                Flaky.n += 1
                if Flaky.n == 1:
                    return 409, {"error_envelope": {"code": "RECORD_CHANGED", "retryable": True}}
                return 200, {"success": True, "outcome": "written"}
        out = script.apply_writes(Flaky([]), "enceladus", ["T1"], "r", max_rps=0, sleep=lambda s: None)
        self.assertEqual((1, 0, 2), (out["written"], out["failed"], Flaky.n))

    def test_the_script_holds_no_table_credentials(self):
        text = _src(_REPO, "tools", "backfill_task_lifecycle_stamps.py")
        tree = ast.parse(text)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertTrue({"boto3", "botocore"}.isdisjoint(imported), imported)
        strings = " ".join(n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str))
        for token in ("devops-project-tracker", "dynamodb", "AWS_ACCESS_KEY", "AWS_SECRET", "AWS_PROFILE",
                      "update_item", "put_item"):
            self.assertNotIn(token, strings.replace("--confirm", ""), token)
        # the only secret it reads is the tracker API's HTTP key
        self.assertEqual(("ENCELADUS_COORDINATION_INTERNAL_API_KEY", "COORDINATION_INTERNAL_API_KEY"),
                         script.KEY_ENV_VARS)


if __name__ == "__main__":
    unittest.main()
