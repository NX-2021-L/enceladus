"""Signed v1 cursors (DVP-TSK-919): FT-03 cursor-signing contract on the feed_query handler code."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import corpus  # noqa: E402
import cursor_codec  # noqa: E402

NOW = 1788228600.0  # 2026-09-01T02:10:00Z


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    monkeypatch.setenv("FEED_CURSOR_KEYS", json.dumps({"k1": "secret-one", "k2": "secret-two"}))
    monkeypatch.setenv("FEED_CURSOR_ACTIVE_KID", "k1")
    monkeypatch.delenv("COORDINATION_INTERNAL_API_KEY", raising=False)


def _entries(n=7):
    return [
        {"record_id": f"ENC-TSK-{i}", "record_type": "task", "project_id": "enceladus", "title": f"t{i}",
         "updated_at": f"2026-09-01T00:{i:02d}:00Z", "source": "tracker",
         "record_key": corpus.tracker_record_key("enceladus", f"ENC-TSK-{i}"), "attrs": {}}
        for i in range(1, n + 1)
    ]


def test_cursor_wire_shape_matches_the_kit_envelope():
    cur = cursor_codec.encode("abc", "feed_query:v1", {"sort": "x"}, now=NOW)
    body, tag = cur.split(".")
    payload = json.loads(cursor_codec._b64d(body))
    assert list(payload) == sorted(payload)  # keys sorted, compact
    assert payload["v"] == 1 and payload["k"] == "abc" and payload["kid"] == "k1"
    assert payload["exp"] == int(NOW) + 86400 and payload["scope"] == "feed_query:v1"
    assert payload["f"] == cursor_codec.hash_filter({"sort": "x"})
    assert len(cursor_codec._b64d(tag)) == 32


def test_hash_filter_is_key_order_independent_and_matches_the_kit_algorithm():
    assert cursor_codec.hash_filter({"a": 1, "b": 2}) == cursor_codec.hash_filter({"b": 2, "a": 1})
    # sha256('{}')[:12] base64url, the kit's hashFilter({})
    assert cursor_codec.hash_filter(None) == "RBNvo1WzZ4oRRq0W"


@pytest.mark.parametrize("mutate,reason", [
    (lambda c: c[:-2] + ("AA" if not c.endswith("AA") else "BB"), "bad_tag"),
    (lambda c: "x." + c.split(".")[1], "malformed"),
])
def test_tampered_cursors_are_rejected(mutate, reason):
    cur = cursor_codec.encode("abc", "feed_query:v1", None, now=NOW)
    with pytest.raises(cursor_codec.CursorInvalid) as e:
        cursor_codec.decode(mutate(cur), "feed_query:v1", None, now=NOW)
    assert e.value.reason == reason and e.value.code == "cursor_invalid" and e.value.status == 400


def test_expired_foreign_filter_foreign_scope_and_unknown_kid():
    cur = cursor_codec.encode("abc", "feed_query:v1", {"sort": "x"}, now=NOW)
    assert cursor_codec.decode(cur, "feed_query:v1", {"sort": "x"}, now=NOW + 10) == ("abc", 1)
    for args, reason in [
        (("feed_query:v1", {"sort": "x"}, NOW + 86401), "expired"),
        (("feed_query:v1", {"sort": "y"}, NOW), "foreign_filter"),
        (("other:v1", {"sort": "x"}, NOW), "foreign_scope"),
    ]:
        with pytest.raises(cursor_codec.CursorInvalid) as e:
            cursor_codec.decode(cur, args[0], args[1], now=args[2])
        assert e.value.reason == reason


def test_key_rotation_old_kid_still_verifies(monkeypatch):
    cur = cursor_codec.encode("abc", "s", None, now=NOW)  # signed with k1
    monkeypatch.setenv("FEED_CURSOR_ACTIVE_KID", "k2")
    assert cursor_codec.decode(cur, "s", None, now=NOW)[0] == "abc"
    assert json.loads(cursor_codec._b64d(cursor_codec.encode("z", "s", None, now=NOW).split(".")[0]))["kid"] == "k2"
    monkeypatch.setenv("FEED_CURSOR_KEYS", json.dumps({"k2": "secret-two"}))
    with pytest.raises(cursor_codec.CursorInvalid):
        cursor_codec.decode(cur, "s", None, now=NOW)


def test_unsigned_v0_accepted_only_inside_the_migration_window():
    legacy = corpus._legacy_cursor("2026-09-01T00:01:00Z", "tracker:enceladus:ENC-TSK-1")
    assert corpus.decode_cursor(legacy) == ("2026-09-01T00:01:00Z", "tracker:enceladus:ENC-TSK-1")
    after = cursor_codec.V0_ACCEPTANCE_END_MS / 1000
    with pytest.raises(cursor_codec.CursorInvalid) as e:
        cursor_codec.decode(legacy, corpus.CURSOR_SCOPE, None, now=after)
    assert e.value.reason == "unsigned_not_allowed"
    assert cursor_codec.V0_ACCEPTANCE_END_MS == 1799539200000  # 2027-01-10T00:00:00Z


def test_corpus_pages_carry_signed_cursors_and_walk_without_gaps():
    entries = _entries(7)
    seen, cursor = [], ""
    while True:
        query = corpus.parse_corpus_query({"limit": "3", "sort": "updated_at_desc", "cursor": cursor})
        page = corpus.paginate_corpus(entries, query)
        seen += [i["record_id"] for i in page["items"]]
        cursor = page["next_cursor"] or ""
        if not cursor:
            break
        assert "." in cursor and cursor.count(".") == 1  # signed v1, no LastEvaluatedKey shape
        assert "sort_value" not in json.dumps(cursor_codec._b64d(cursor.split(".")[0]).decode())
    assert seen == [f"ENC-TSK-{i}" for i in range(7, 0, -1)]


def test_a_cursor_is_bound_to_its_filter_and_sort():
    entries = _entries(7)
    q = corpus.parse_corpus_query({"limit": "3", "sort": "updated_at_desc"})
    cur = corpus.paginate_corpus(entries, q)["next_cursor"]
    assert corpus.decode_cursor(cur, corpus.cursor_filter(q)) is not None
    other = corpus.parse_corpus_query({"limit": "3", "sort": "title_asc"})
    assert corpus.decode_cursor(cur, corpus.cursor_filter(other)) is None
    assert corpus.decode_cursor(cur[:-3] + "AAA", corpus.cursor_filter(q)) is None


def test_without_any_key_the_lambda_keeps_minting_the_legacy_cursor(monkeypatch):
    monkeypatch.delenv("FEED_CURSOR_KEYS", raising=False)
    cur = corpus.encode_cursor("2026-09-01T00:01:00Z", "tracker:enceladus:ENC-TSK-1")
    assert "." not in cur and corpus.decode_cursor(cur)[1] == "tracker:enceladus:ENC-TSK-1"


def test_key_derived_from_the_existing_internal_key(monkeypatch):
    monkeypatch.delenv("FEED_CURSOR_KEYS", raising=False)
    monkeypatch.delenv("FEED_CURSOR_ACTIVE_KID", raising=False)
    monkeypatch.setenv("COORDINATION_INTERNAL_API_KEY", "internal")
    cur = corpus.encode_cursor("2026-09-01T00:01:00Z", "tracker:enceladus:ENC-TSK-1")
    assert "." in cur and corpus.decode_cursor(cur) == ("2026-09-01T00:01:00Z", "tracker:enceladus:ENC-TSK-1")
