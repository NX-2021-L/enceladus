"""Unit tests for the stale_checkout_monitor detection core (ENC-TSK-H51 / ENC-ISS-142
gate #3). Exercises the pure detect_stale() — no AWS — with a fixed `now`."""
import importlib.util
import pathlib
import sys
from datetime import datetime, timezone

MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("stale_checkout_monitor", MODULE_PATH)
mod = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)

NOW = datetime(2026, 6, 23, 20, 0, 0, tzinfo=timezone.utc)


def _task(**kw):
    base = {"record_type": "task", "item_id": "ENC-TSK-X", "status": "in-progress"}
    base.update(kw)
    return base


def test_long_held_checkout_is_flagged():
    items = [
        _task(
            item_id="ENC-TSK-OLD",
            checkout_state="checked_out",
            checked_out_by="agent-session-1",
            checked_out_at="2026-06-23T14:00:00Z",  # 6h before NOW
        )
    ]
    sigs = mod.detect_stale(items, NOW, 240)
    assert len(sigs) == 1
    s = sigs[0]
    assert s["record_id"] == "ENC-TSK-OLD"
    assert s["reason"] == "long_held_checkout"
    assert s["checked_out_by"] == "agent-session-1"
    assert s["age_minutes"] == 360
    assert set(["record_id", "checked_out_by", "checked_out_at", "age_minutes"]).issubset(s)


def test_fresh_checkout_not_flagged():
    items = [
        _task(
            checkout_state="checked_out",
            checked_out_at="2026-06-23T19:50:00Z",  # 10 min before NOW
        )
    ]
    assert mod.detect_stale(items, NOW, 240) == []


def test_stale_in_progress_without_checkout_is_flagged():
    items = [
        _task(
            item_id="ENC-TSK-IP",
            status="in-progress",
            checkout_state="checked_in",
            updated_at="2026-06-23T10:00:00Z",  # 10h before NOW
        )
    ]
    sigs = mod.detect_stale(items, NOW, 240)
    assert len(sigs) == 1
    assert sigs[0]["reason"] == "stale_in_progress"
    assert sigs[0]["age_minutes"] == 600


def test_threshold_is_configurable_boundary():
    items = [
        _task(
            checkout_state="checked_out",
            checked_out_at="2026-06-23T19:00:00Z",  # exactly 60 min before NOW
        )
    ]
    assert mod.detect_stale(items, NOW, 61) == []  # below threshold
    assert len(mod.detect_stale(items, NOW, 60)) == 1  # at threshold (>=)


def test_non_task_records_ignored():
    items = [
        {"record_type": "issue", "item_id": "ENC-ISS-1", "status": "in-progress",
         "updated_at": "2026-01-01T00:00:00Z"},
        {"record_type": "document", "item_id": "DOC-1"},
    ]
    assert mod.detect_stale(items, NOW, 240) == []


def test_long_held_checkout_takes_precedence_over_in_progress():
    # a checked-out, in-progress task that is stale on both axes yields ONE signal
    items = [
        _task(
            item_id="ENC-TSK-BOTH",
            status="in-progress",
            checkout_state="checked_out",
            checked_out_at="2026-06-23T10:00:00Z",
            updated_at="2026-06-23T10:00:00Z",
        )
    ]
    sigs = mod.detect_stale(items, NOW, 240)
    assert len(sigs) == 1
    assert sigs[0]["reason"] == "long_held_checkout"


def test_parse_iso_tolerates_z_and_naive():
    assert mod.parse_iso("2026-06-23T20:00:00Z").tzinfo is not None
    assert mod.parse_iso("2026-06-23T20:00:00").tzinfo is timezone.utc
    assert mod.parse_iso("") is None
    assert mod.parse_iso(None) is None
    assert mod.parse_iso("not-a-date") is None


def test_threshold_minutes_env_fallback(monkeypatch=None):
    import os
    os.environ.pop("STALE_CHECKOUT_THRESHOLD_MINUTES", None)
    assert mod.threshold_minutes() == 240
    os.environ["STALE_CHECKOUT_THRESHOLD_MINUTES"] = "30"
    assert mod.threshold_minutes() == 30
    os.environ["STALE_CHECKOUT_THRESHOLD_MINUTES"] = "bogus"
    assert mod.threshold_minutes() == 240
    os.environ.pop("STALE_CHECKOUT_THRESHOLD_MINUTES", None)
