"""Tests for mcp_server/meta_support.py's result_metadata() lift rules.

ENC-TSK-Q15 (O3.2): census payloads (mode=census on tracker_list) carry
count / exhausted / count_truncated / excluded_types fields that a plain
records-page payload never has. result_metadata() must lift the census
fields into the meta-tool's `metadata` block when present, while leaving
the plain-list metadata shape byte-identical to today.
"""

from mcp_server.meta_support import result_metadata


def test_result_metadata_lifts_census_fields():
    payload = {
        "count": 437,
        "count_truncated": True,
        "exhausted": False,
        "excluded_types": ["escalation"],
        "pages": [{"cursor": "c1", "first": {"id": "ENC-TSK-1"}, "last": {"id": "ENC-TSK-25"}, "n": 25}],
        "page_size": 25,
        "as_of": {"kind": "wall_clock+max_updated_at", "started_at": "t0", "max_updated_at": "t0"},
        "order": "unspecified",
        "by_type": {"task": 437},
    }

    metadata = result_metadata(payload)

    assert metadata["count"] == 437
    assert metadata["count_truncated"] is True
    assert metadata["exhausted"] is False
    assert metadata["excluded_types"] == ["escalation"]
    # No pagination.next_cursor / next_cursor on a census payload.
    assert "next_cursor" not in metadata


def test_result_metadata_plain_list_unchanged():
    """A plain (non-census) tracker_list-shaped payload must lift exactly the
    same fields it does today -- no new keys appear when the census-only
    fields are absent."""
    payload = {
        "records": [{"id": "ENC-TSK-1"}],
        "count": 1,
        "total": 1,
        "next_cursor": "cursor-1",
    }

    metadata = result_metadata(payload)

    assert metadata == {"next_cursor": "cursor-1", "count": 1}
    assert "exhausted" not in metadata
    assert "count_truncated" not in metadata
    assert "excluded_types" not in metadata


if __name__ == "__main__":
    import sys

    failures = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"  FAIL {name}: {exc}")
    if failures:
        print(f"\n{failures} test(s) FAILED")
        sys.exit(1)
    print("\nAll tests passed!")
