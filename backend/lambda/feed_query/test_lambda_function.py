"""Unit tests for feed_query incremental delta behavior."""

from __future__ import annotations

import importlib.util
import json
import os


_SPEC = importlib.util.spec_from_file_location(
    "feed_query_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
feed_query = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(feed_query)


def _feed_get_event(since: str) -> dict:
    return {
        "requestContext": {"http": {"method": "GET"}},
        "rawPath": "/api/v1/feed",
        "headers": {"Cookie": "enceladus_id_token=test-token"},
        "queryStringParameters": {"since": since},
    }


def test_since_delta_applies_lookback_and_returns_no_cache(monkeypatch):
    monkeypatch.setattr(feed_query, "_verify_token", lambda _token: {"sub": "u-1"})

    captured = {}

    def _fake_query_incremental(since_iso: str):
        captured["since_iso"] = since_iso
        # Returns (tasks, issues, features, lessons, plans, closed_ids).
        # Plans were added in ENC-FTR-058 (ed65d01); keeping the tuple shape
        # in sync with the real function signature.
        return [], [], [], [], [], ["ENC-TSK-123"]

    monkeypatch.setattr(feed_query, "_query_incremental", _fake_query_incremental)

    resp = feed_query.lambda_handler(_feed_get_event("2026-02-25T12:00:10Z"), None)

    assert resp["statusCode"] == 200
    assert captured["since_iso"] == "2026-02-25T12:00:00Z"
    assert resp["headers"]["Cache-Control"] == "no-cache, no-store, must-revalidate"
    payload = json.loads(resp["body"])
    assert payload["closed_ids"] == ["ENC-TSK-123"]
    # Delta payload must also surface plans and lessons keys, even when empty,
    # so the PWA LiveFeedContext can reliably read data.lessons / data.plans.
    assert "lessons" in payload
    assert "plans" in payload


def test_invalid_since_returns_400(monkeypatch):
    monkeypatch.setattr(feed_query, "_verify_token", lambda _token: {"sub": "u-1"})

    resp = feed_query.lambda_handler(_feed_get_event("not-a-date"), None)

    assert resp["statusCode"] == 400
    payload = json.loads(resp["body"])
    assert "since" in payload["error"]


# ---------------------------------------------------------------------------
# _ddb_history defensive behavior (ENC-TSK-C31)
#
# PR #239 (commit a4b3751) introduced _ddb_history() and started calling it
# from all five _transform_*_from_ddb helpers. A crash in _ddb_history for
# any single record propagated out of _query_all_records and returned HTTP
# 500 for the full-refresh /api/v1/feed endpoint. In the PWA, doFullRefresh
# caught the 500 as a generic error, leaving hasLiveSnapshot=false; tasks,
# issues, and features fell back to S3 (still visible) but lessons and
# plans have no S3 fallback in useFeed.ts and collapsed to empty arrays —
# which is exactly the ENC-ISS-176 / ENC-TSK-C29 / ENC-TSK-C31 symptom.
#
# These tests lock in that _ddb_history tolerates every input shape we
# have observed or can reasonably imagine DynamoDB serving.
# ---------------------------------------------------------------------------


def test_ddb_history_missing_attribute_returns_empty():
    item = {"item_id": {"S": "ENC-TSK-123"}}
    assert feed_query._ddb_history(item) == []


def test_ddb_history_none_attribute_returns_empty():
    # Attribute key present but value is None (not a DDB wire-format dict).
    # Prior bug: `item.get("history", {})` returns None when the key exists,
    # then `None.get("L")` raised AttributeError and crashed the transform.
    item = {"item_id": {"S": "ENC-TSK-123"}, "history": None}
    assert feed_query._ddb_history(item) == []


def test_ddb_history_non_dict_attribute_returns_empty():
    item = {"item_id": {"S": "ENC-TSK-123"}, "history": "not-a-dict"}
    assert feed_query._ddb_history(item) == []


def test_ddb_history_non_list_l_value_returns_empty():
    item = {"item_id": {"S": "ENC-TSK-123"}, "history": {"L": "not-a-list"}}
    assert feed_query._ddb_history(item) == []


def test_ddb_history_empty_list_returns_empty():
    item = {"item_id": {"S": "ENC-TSK-123"}, "history": {"L": []}}
    assert feed_query._ddb_history(item) == []


def test_ddb_history_non_dict_entry_skipped():
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {"L": ["not-a-dict", 42, None]},
    }
    assert feed_query._ddb_history(item) == []


def test_ddb_history_entry_missing_m_skipped():
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {"L": [{"S": "wrong-type-marker"}]},
    }
    assert feed_query._ddb_history(item) == []


def test_ddb_history_entry_with_m_none_skipped():
    # The exact shape that most likely caused the live 500: entry["M"] is
    # None (rather than a dict). Prior code did `m = entry["M"]` then
    # `m.get("timestamp", {})` which raised AttributeError on None.
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {"L": [{"M": None}]},
    }
    assert feed_query._ddb_history(item) == []


def test_ddb_history_entry_with_empty_m_normalized():
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {"L": [{"M": {}}]},
    }
    assert feed_query._ddb_history(item) == [
        {"timestamp": "", "status": "", "description": ""}
    ]


def test_ddb_history_field_value_is_bare_string():
    # The inner field ("timestamp") is stored as a bare string instead of a
    # {'S': ...} wire-format dict. Prior code did
    # `m.get("timestamp", {}).get("S", "")` and crashed with AttributeError
    # on the bare string.
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {
            "L": [
                {
                    "M": {
                        "timestamp": "raw-string",
                        "status": {"S": "created"},
                        "description": {"S": "ok"},
                    }
                }
            ]
        },
    }
    assert feed_query._ddb_history(item) == [
        {"timestamp": "", "status": "created", "description": "ok"}
    ]


def test_ddb_history_field_s_value_not_string():
    # Extremely defensive: S field with a non-string nested value.
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {
            "L": [
                {
                    "M": {
                        "timestamp": {"S": 12345},
                        "status": {"S": "ok"},
                        "description": {"S": None},
                    }
                }
            ]
        },
    }
    assert feed_query._ddb_history(item) == [
        {"timestamp": "", "status": "ok", "description": ""}
    ]


def test_ddb_history_normal_entry_extracted():
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {
            "L": [
                {
                    "M": {
                        "timestamp": {"S": "2026-04-07T11:00:00Z"},
                        "status": {"S": "created"},
                        "description": {"S": "Task created via API"},
                    }
                },
                {
                    "M": {
                        "timestamp": {"S": "2026-04-07T11:05:00Z"},
                        "status": {"S": "in-progress"},
                        "description": {"S": "Checked out"},
                    }
                },
            ]
        },
    }
    result = feed_query._ddb_history(item)
    assert len(result) == 2
    assert result[0]["status"] == "created"
    assert result[1]["status"] == "in-progress"
    assert result[1]["description"] == "Checked out"


def test_ddb_history_caps_at_max_entries():
    entries = [
        {
            "M": {
                "timestamp": {"S": f"2026-04-07T11:00:{i:02d}Z"},
                "status": {"S": "worklog"},
                "description": {"S": f"entry {i}"},
            }
        }
        for i in range(feed_query.MAX_HISTORY_ENTRIES + 10)
    ]
    item = {"item_id": {"S": "ENC-TSK-123"}, "history": {"L": entries}}
    result = feed_query._ddb_history(item)
    assert len(result) == feed_query.MAX_HISTORY_ENTRIES
    # Keeps the most recent (tail-end) entries.
    assert result[-1]["description"] == f"entry {feed_query.MAX_HISTORY_ENTRIES + 9}"


def test_ddb_history_mixed_good_and_bad_entries():
    # A single bad entry must not poison the whole history array.
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {
            "L": [
                {
                    "M": {
                        "timestamp": {"S": "2026-04-07T11:00:00Z"},
                        "status": {"S": "created"},
                        "description": {"S": "good entry 1"},
                    }
                },
                {"M": None},  # bad: M is None
                "not-a-dict",  # bad: not a dict
                {
                    "M": {
                        "timestamp": {"S": "2026-04-07T11:05:00Z"},
                        "status": {"S": "worklog"},
                        "description": {"S": "good entry 2"},
                    }
                },
            ]
        },
    }
    result = feed_query._ddb_history(item)
    assert len(result) == 2
    assert result[0]["description"] == "good entry 1"
    assert result[1]["description"] == "good entry 2"
