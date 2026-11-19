"""test_projection_guard_stamps_s96_0c.py -- the W1 backfill must not storm convergence_telemetry
(ENC-TSK-S96-0C, ENC-PLN-108 W1.3).

W1 dates roughly 7,878 historical task records with first_checked_out_at,
closed_at and closed_at_unknown. Those are MARKER writes (write_kind="marker",
no version_seq) precisely so the stream consumers drop them: without the guard
every one of those records would be reprocessed here in a single burst.

The guard is a subset test against PROJECTION_ONLY_ATTRS, and it cuts both ways,
so both directions are pinned here:

  * a backfill-shaped diff IS dropped, and
  * a real close and a real checkout are NOT -- they move status, updated_at,
    sync_version, checkout_state and friends, none of which is projection-only,
    so a genuine lifecycle write can never become a subset of that set.

The second half is the one that would hurt if it broke: silently dropping real
closes would leave the search index, the audit trail and the convergence counters
disagreeing with the tracker, and nothing would report it.

Run: python3 -m pytest test_projection_guard_stamps_s96_0c.py -q
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("COUNTER_TABLE", "test-counters")
_HERE = os.path.dirname(__file__)
sys.path.insert(0, _HERE)
_spec = importlib.util.spec_from_file_location(
    "convergence_telemetry_projection_guard_s96_0c", os.path.join(_HERE, "lambda_function.py"))
m = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = m
_spec.loader.exec_module(m)


def _img(**kw):
    return {k: {"S": str(v)} for k, v in kw.items()}


class StampsAreProjectionOnlyTests(unittest.TestCase):
    def test_the_three_stamps_are_listed(self):
        for attr in ("first_checked_out_at", "closed_at", "closed_at_unknown"):
            self.assertIn(attr, m.PROJECTION_ONLY_ATTRS, attr)

    def test_the_preexisting_members_are_untouched(self):
        for attr in ("projection_status", "projected_version_seq", "t_projected",
                     "feed_published_version_seq", "write_kind"):
            self.assertIn(attr, m.PROJECTION_ONLY_ATTRS, attr)

    def test_backfill_shaped_marker_write_is_dropped(self):
        old = _img(status="closed", write_kind="governed")
        new = _img(status="closed", write_kind="marker",
                   closed_at="2026-03-01T00:00:00Z",
                   first_checked_out_at="2026-02-01T00:00:00Z")
        self.assertTrue(m._projection_only_diff(old, new),
                        "the backfill must be invisible to this consumer")

    def test_backfill_waiver_marker_is_dropped(self):
        old = _img(status="closed", write_kind="governed")
        new = _img(status="closed", write_kind="marker",
                   closed_at_unknown="{unknown}")
        self.assertTrue(m._projection_only_diff(old, new))

    def test_a_real_close_is_NOT_dropped(self):
        old = _img(status="merged-main", updated_at="t0", sync_version="1")
        new = _img(status="closed", updated_at="t1", sync_version="2",
                   closed_at="2026-11-19T00:00:00Z", write_kind="governed")
        self.assertFalse(m._projection_only_diff(old, new),
                         "a governed close must still reach this consumer")

    def test_a_real_checkout_is_NOT_dropped(self):
        old = _img(status="open", updated_at="t0")
        new = _img(status="in-progress", updated_at="t1",
                   checkout_state="checked_out", checked_out_by="ENC-SES-1",
                   first_checked_out_at="2026-11-19T00:00:00Z")
        self.assertFalse(m._projection_only_diff(old, new))

    def test_a_stamp_write_that_also_bumps_updated_at_is_NOT_dropped(self):
        """The backfill must touch the stamps and write_kind ONLY.

        If it also moved updated_at the diff would stop being a subset and the
        burst this guard exists to prevent would come back. Pinned so that
        ENC-TSK-S96-0D cannot quietly reintroduce it.
        """
        old = _img(write_kind="governed", updated_at="t0")
        new = _img(write_kind="marker", updated_at="t1",
                   closed_at="2026-03-01T00:00:00Z")
        self.assertFalse(m._projection_only_diff(old, new))

    def test_no_diff_at_all_is_not_a_projection_marker(self):
        same = _img(status="closed", write_kind="governed")
        self.assertFalse(m._projection_only_diff(same, dict(same)))

    def test_record_wrapper_agrees_with_the_diff(self):
        old = _img(status="closed", write_kind="governed")
        new = _img(status="closed", write_kind="marker",
                   closed_at="2026-03-01T00:00:00Z")
        self.assertTrue(m._record_is_projection_marker(
            {"dynamodb": {"OldImage": old, "NewImage": new}}))
        self.assertFalse(m._record_is_projection_marker({}))


if __name__ == "__main__":
    unittest.main()
