"""Unit tests for the observation clock on the full-record feed transforms (DVP-TSK-765).

tracker_mutation's POST .../log with observation_only=true writes
last_observed_at and observation_count. Every _transform_*_from_ddb helper is a
field whitelist, so without an explicit addition the PWA feed would drop both.
They must also never crash a transform: one bad record 500s the whole feed
(ENC-TSK-C31).
"""

from __future__ import annotations

import importlib.util
import os

_SPEC = importlib.util.spec_from_file_location(
    "feed_query_observation_dvp765",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
feed_query = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(feed_query)

OBSERVED_AT = "2026-10-07T12:00:00Z"
RECORD_TYPES = ("task", "issue", "feature", "lesson", "plan")


def _item(record_type, **extra):
    item = {
        "item_id": {"S": "ENC-%s-765" % record_type.upper()[:3]},
        "record_type": {"S": record_type},
        "title": {"S": "observation subject"},
        "status": {"S": "open"},
        "updated_at": {"S": "2026-09-01T00:00:00Z"},
    }
    item.update(extra)
    return item


def test_every_full_record_transform_carries_both_fields():
    for record_type in RECORD_TYPES:
        out = feed_query._TRANSFORM[record_type](
            _item(
                record_type,
                last_observed_at={"S": OBSERVED_AT},
                observation_count={"N": "2"},
            ),
            "enceladus",
        )
        assert out["last_observed_at"] == OBSERVED_AT, record_type
        assert out["observation_count"] == 2, record_type
        # The observation clock is not the state clock.
        assert out["updated_at"] == "2026-09-01T00:00:00Z", record_type


def test_a_never_observed_record_reads_none_and_zero():
    for record_type in RECORD_TYPES:
        out = feed_query._TRANSFORM[record_type](_item(record_type), "enceladus")
        assert out["last_observed_at"] is None, record_type
        assert out["observation_count"] == 0, record_type


def test_malformed_observation_attributes_never_crash_a_transform():
    for record_type in RECORD_TYPES:
        for extra in (
            {"last_observed_at": None, "observation_count": None},
            {"last_observed_at": {"N": "1"}, "observation_count": {"S": "two"}},
            {"last_observed_at": "not-a-dict", "observation_count": {"N": "not-a-number"}},
        ):
            out = feed_query._TRANSFORM[record_type](_item(record_type, **extra), "enceladus")
            assert out["last_observed_at"] is None, (record_type, extra)
            assert out["observation_count"] == 0, (record_type, extra)


def test_the_minimal_projections_do_not_carry_them():
    """Snapshot rows and corpus/delta entries are deliberately minimal."""
    entry = feed_query._delta_corpus_entry(
        _item("issue", last_observed_at={"S": OBSERVED_AT}, observation_count={"N": "2"}),
        "enceladus",
    )
    assert entry is not None
    flat = repr(entry)
    assert "last_observed_at" not in flat
    assert "observation_count" not in flat
