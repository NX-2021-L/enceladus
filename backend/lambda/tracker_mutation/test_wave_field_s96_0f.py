"""ENC-TSK-S96-0F (ENC-PLN-108 W1.6) -- the optional `wave` field on tracker.task.

DOC-5E1E205FA664 ruling D-20 and sections 5.3 and 5.4. `wave` is an AUTHORED, optional,
plain string on task records. Three merged consumers read it without interpretation
(feed_query lens_attrs -> corpus `wave`; appsync_feed_publisher -> `recordWave`; the
ui-v2 Plans wave resolver), so the contract pinned here is deliberately narrow:

  * tracker.create and tracker.set accept it on a task and RETURN it;
  * both reject it on every other record type with HTTP 400, through the same helpers
    that already police is_child / transition_type (create) and primary_task (set);
  * the value is a str, trimmed, <= 64 characters, no control characters; an empty or
    whitespace-only value means "no wave" (omitted at create, stored as "" by set);
  * it is NOT a reserved field: it is in none of _W11_SERVER_STAMPED_TIMESTAMPS,
    _F41_RESERVED_COUNTER_FIELDS or _RESERVED_OVERRIDE_PATHS, and a client can set it.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

_HERE = os.path.dirname(__file__)
sys.path.insert(0, _HERE)
_spec = importlib.util.spec_from_file_location(
    "tracker_mutation_wave_field_s96_0f",
    os.path.join(_HERE, "lambda_function.py"),
)
tm = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)

NON_TASK_TYPES = ("issue", "feature", "plan", "lesson", "generation")


def _task_item(item_id="ENC-TSK-001", extra=None):
    item = {
        "project_id": {"S": "enceladus"},
        "record_id": {"S": f"task#{item_id}"},
        "item_id": {"S": item_id},
        "status": {"S": "open"},
        "record_type": {"S": "task"},
        "sync_version": {"N": "1"},
        "history": {"L": []},
        "checkout_count": {"N": "0"},
        "closed_count": {"N": "0"},
    }
    if extra:
        item.update(extra)
    return item


def _item_for(record_type, record_id):
    return {
        "project_id": {"S": "enceladus"},
        "record_id": {"S": f"{record_type}#{record_id}"},
        "item_id": {"S": record_id},
        "status": {"S": "open"},
        "record_type": {"S": record_type},
        "sync_version": {"N": "1"},
        "history": {"L": []},
    }


def _envelope(resp):
    return json.loads(resp.get("body", "{}"))


def _create(record_type, **extras):
    """Drive _handle_create_record; return (response, captured put_item Items)."""
    captured = []

    def fake_put_item(TableName, Item, ConditionExpression=None):
        captured.append(Item)
        return {}

    ddb = MagicMock()
    ddb.put_item.side_effect = fake_put_item
    ddb.update_item.return_value = {}
    body = {"title": "Wave field task", "acceptance_criteria": [{"description": "x"}]}
    body.update(extras)
    with patch.object(tm, "_get_ddb", return_value=ddb), \
            patch.object(tm, "ENABLE_LESSON_PRIMITIVE", True), \
            patch.object(tm, "_get_project_prefix", return_value="ENC"), \
            patch.object(tm, "_next_record_id", return_value="ENC-TSK-999"):
        resp = tm._handle_create_record("enceladus", record_type, body)
    return resp, captured


def _set(record_type, record_id, value, *, raw_item=None):
    """Drive _handle_update_field for field=wave; return (response, ddb mock)."""
    ddb = MagicMock()
    ddb.get_item.return_value = {"Item": raw_item or _item_for(record_type, record_id)}
    ddb.update_item.return_value = {}
    body = {"field": "wave", "value": value, "provider": "codex"}
    # Lesson writes are behind ENABLE_LESSON_PRIMITIVE; turn it on so the wave rule, not the
    # feature flag, is what the lesson case exercises.
    with patch.object(tm, "_get_ddb", return_value=ddb), \
            patch.object(tm, "ENABLE_LESSON_PRIMITIVE", True):
        resp = tm._handle_update_field("enceladus", record_type, record_id, body)
    return resp, ddb


class TestWaveOnCreate(unittest.TestCase):
    def test_accepted_stored_and_returned(self):
        resp, items = _create("task", wave="W1.6")
        self.assertEqual(resp["statusCode"], 201, resp.get("body"))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["wave"], {"S": "W1.6"})
        self.assertEqual(_envelope(resp).get("wave"), "W1.6")

    def test_absent_when_not_supplied(self):
        resp, items = _create("task")
        self.assertEqual(resp["statusCode"], 201, resp.get("body"))
        self.assertNotIn("wave", items[0])
        self.assertNotIn("wave", _envelope(resp))

    def test_none_is_treated_as_not_supplied(self):
        resp, items = _create("task", wave=None)
        self.assertEqual(resp["statusCode"], 201, resp.get("body"))
        self.assertNotIn("wave", items[0])

    def test_value_is_trimmed(self):
        resp, items = _create("task", wave="  W2.1  ")
        self.assertEqual(resp["statusCode"], 201, resp.get("body"))
        self.assertEqual(items[0]["wave"], {"S": "W2.1"})
        self.assertEqual(_envelope(resp).get("wave"), "W2.1")

    def test_empty_and_whitespace_only_are_omitted_not_stored(self):
        for blank in ("", "   ", "\t "):
            with self.subTest(blank=repr(blank)):
                resp, items = _create("task", wave=blank)
                self.assertEqual(resp["statusCode"], 201, resp.get("body"))
                self.assertNotIn("wave", items[0])
                self.assertNotIn("wave", _envelope(resp))

    def test_max_length_boundary(self):
        ok, items = _create("task", wave="W" * tm._WAVE_MAX_LENGTH)
        self.assertEqual(ok["statusCode"], 201, ok.get("body"))
        self.assertEqual(items[0]["wave"], {"S": "W" * 64})
        over, items = _create("task", wave="W" * (tm._WAVE_MAX_LENGTH + 1))
        self.assertEqual(over["statusCode"], 400)
        self.assertEqual(items, [])
        self.assertIn("wave", _envelope(over)["error"])

    def test_length_counts_after_trimming(self):
        resp, items = _create("task", wave="  " + "W" * 64 + "  ")
        self.assertEqual(resp["statusCode"], 201, resp.get("body"))
        self.assertEqual(items[0]["wave"], {"S": "W" * 64})

    def test_non_string_values_rejected(self):
        for bad in (3, 1.5, True, ["W1"], {"id": "W1"}):
            with self.subTest(bad=repr(bad)):
                resp, items = _create("task", wave=bad)
                self.assertEqual(resp["statusCode"], 400)
                self.assertEqual(items, [])
                self.assertIn("must be a string", _envelope(resp)["error"])

    def test_control_characters_and_line_breaks_rejected(self):
        for bad in ("W1\nW2", "W1\tW2", "W1\x00"):
            with self.subTest(bad=repr(bad)):
                resp, items = _create("task", wave=bad)
                self.assertEqual(resp["statusCode"], 400)
                self.assertEqual(items, [])

    def test_unicode_label_accepted(self):
        resp, items = _create("task", wave="Wave 2 — Reconcile")
        self.assertEqual(resp["statusCode"], 201, resp.get("body"))
        self.assertEqual(items[0]["wave"], {"S": "Wave 2 — Reconcile"})


class TestWaveRejectedOnNonTaskCreate(unittest.TestCase):
    def test_rejected_with_400_on_every_non_task_type(self):
        for rt in NON_TASK_TYPES:
            with self.subTest(record_type=rt):
                resp, items = _create(rt, wave="W1")
                self.assertEqual(resp["statusCode"], 400)
                self.assertEqual(items, [], "nothing may be written")
                env = _envelope(resp)
                self.assertIn("wave is only valid for task records", env["error"])
                self.assertEqual(env["error_envelope"]["details"]["record_type"], rt)

    def test_rejection_precedes_other_type_specific_validation(self):
        """A bare, otherwise-incomplete issue/feature body still gets the wave message."""
        captured = []
        ddb = MagicMock()
        ddb.put_item.side_effect = lambda **kw: captured.append(kw)
        with patch.object(tm, "_get_ddb", return_value=ddb), \
                patch.object(tm, "ENABLE_LESSON_PRIMITIVE", True):
            for rt in NON_TASK_TYPES:
                resp = tm._handle_create_record("enceladus", rt, {"title": "t", "wave": "W1"})
                self.assertEqual(resp["statusCode"], 400)
                self.assertIn("wave is only valid for task records", _envelope(resp)["error"], rt)
        self.assertEqual(captured, [])

    def test_blank_value_is_also_rejected_on_non_task(self):
        resp, items = _create("issue", wave="")
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(items, [])

    def test_non_task_create_without_wave_is_unaffected(self):
        resp, items = _create("issue", hypothesis="h", evidence=[
            {"description": "d", "steps_to_duplicate": ["s"]}])
        self.assertEqual(resp["statusCode"], 201, resp.get("body"))
        self.assertNotIn("wave", items[0])


class TestWaveOnSet(unittest.TestCase):
    def test_accepted_written_and_returned(self):
        resp, ddb = _set("task", "ENC-TSK-001", "W1.6", raw_item=_task_item())
        self.assertEqual(resp["statusCode"], 200, resp.get("body"))
        env = _envelope(resp)
        self.assertTrue(env["success"])
        self.assertEqual(env["field"], "wave")
        self.assertEqual(env["value"], "W1.6")
        kw = ddb.update_item.call_args.kwargs
        self.assertEqual(kw["ExpressionAttributeNames"], {"#fld": "wave"})
        self.assertEqual(kw["ExpressionAttributeValues"][":val"], {"S": "W1.6"})

    def test_value_is_trimmed_and_echoed_trimmed(self):
        resp, ddb = _set("task", "ENC-TSK-001", "  W2.2 ", raw_item=_task_item())
        self.assertEqual(resp["statusCode"], 200, resp.get("body"))
        self.assertEqual(_envelope(resp)["value"], "W2.2")
        self.assertEqual(ddb.update_item.call_args.kwargs["ExpressionAttributeValues"][":val"], {"S": "W2.2"})

    def test_whitespace_only_clears_to_empty_string(self):
        resp, ddb = _set("task", "ENC-TSK-001", "   ",
                         raw_item=_task_item(extra={"wave": {"S": "W1"}}))
        self.assertEqual(resp["statusCode"], 200, resp.get("body"))
        self.assertEqual(_envelope(resp)["value"], "")
        self.assertEqual(ddb.update_item.call_args.kwargs["ExpressionAttributeValues"][":val"], {"S": ""})

    def test_replaces_an_existing_wave(self):
        resp, ddb = _set("task", "ENC-TSK-001", "W3",
                         raw_item=_task_item(extra={"wave": {"S": "W1"}}))
        self.assertEqual(resp["statusCode"], 200, resp.get("body"))
        self.assertEqual(ddb.update_item.call_args.kwargs["ExpressionAttributeValues"][":val"], {"S": "W3"})

    def test_over_length_rejected_without_write(self):
        resp, ddb = _set("task", "ENC-TSK-001", "W" * 65, raw_item=_task_item())
        self.assertEqual(resp["statusCode"], 400)
        ddb.update_item.assert_not_called()

    def test_non_string_and_control_characters_rejected_without_write(self):
        for bad in (3, True, ["W1"], {"a": 1}, "W1\nW2"):
            with self.subTest(bad=repr(bad)):
                resp, ddb = _set("task", "ENC-TSK-001", bad, raw_item=_task_item())
                self.assertEqual(resp["statusCode"], 400)
                ddb.update_item.assert_not_called()

    def test_none_value_is_a_clear(self):
        resp, ddb = _set("task", "ENC-TSK-001", None, raw_item=_task_item())
        self.assertEqual(resp["statusCode"], 200, resp.get("body"))
        self.assertEqual(ddb.update_item.call_args.kwargs["ExpressionAttributeValues"][":val"], {"S": ""})


class TestWaveRejectedOnNonTaskSet(unittest.TestCase):
    def test_rejected_with_400_on_every_non_task_type(self):
        # "generation" is creatable but has no entry in _TYPE_SEG_TO_SK_PREFIX, so the set path
        # cannot address it at all (pre-existing, unrelated); the four routable types are covered.
        for rt in tuple(t for t in NON_TASK_TYPES if t in tm._TYPE_SEG_TO_SK_PREFIX):
            with self.subTest(record_type=rt):
                rid = f"ENC-{rt[:3].upper()}-001"
                resp, ddb = _set(rt, rid, "W1")
                self.assertEqual(resp["statusCode"], 400, resp.get("body"))
                ddb.update_item.assert_not_called()
                env = _envelope(resp)
                self.assertIn("wave is only valid on task records", env["error"])
                self.assertEqual(env["error_envelope"]["details"]["field"], "wave")


class TestWaveIsAuthoredNotReserved(unittest.TestCase):
    """The opposite of first_checked_out_at / closed_at (W1.1): a client CAN set wave."""

    def test_not_in_any_reserved_set(self):
        self.assertNotIn("wave", tm._W11_SERVER_STAMPED_TIMESTAMPS)
        self.assertNotIn("wave", tm._F41_RESERVED_COUNTER_FIELDS)
        self.assertNotIn("wave", tm._RESERVED_OVERRIDE_PATHS)

    def test_set_does_not_return_reserved_field_error(self):
        resp, _ddb = _set("task", "ENC-TSK-001", "W1.6", raw_item=_task_item())
        self.assertEqual(resp["statusCode"], 200, resp.get("body"))
        env = _envelope(resp)
        self.assertNotEqual((env.get("error_envelope") or {}).get("code"), "RESERVED_FIELD")

    def test_create_does_not_return_reserved_field_error(self):
        resp, _items = _create("task", wave="W1.6")
        self.assertEqual(resp["statusCode"], 201, resp.get("body"))
        env = _envelope(resp)
        self.assertNotEqual((env.get("error_envelope") or {}).get("code"), "RESERVED_FIELD")

    def test_the_stamps_are_still_reserved_control(self):
        """Control: the guard that would catch wave if it were reserved does fire for the stamps."""
        resp, _items = _create("task", closed_at="2026-01-01T00:00:00Z")
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(_envelope(resp)["error_envelope"]["code"], "RESERVED_FIELD")


if __name__ == "__main__":
    unittest.main()
