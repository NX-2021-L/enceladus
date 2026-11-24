"""ENC-TSK-S97-0B (ENC-PLN-108 W2.2): optional lineage/lifecycle fields on the live event.

The /feed/updates payload gains recordCreatedAt, recordParent, recordFirstCheckedOutAt,
recordClosedAt and recordWave. Each is omitted when the source record does not carry the
value; schemaVersion stays 2.

Named to sort beside test_lambda_function.py; loads the module under its own unique name via
the same sys.path entry (this directory) the rest of the suite already uses.

Run: python3 -m pytest test_live_event_fields_s97_0b.py -q
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys

import pytest

os.environ.setdefault("APPSYNC_EVENTS_HTTP_ENDPOINT", "example.appsync-api.us-west-2.amazonaws.com")
os.environ.setdefault("APPSYNC_EVENTS_API_KEY", "test-key")
os.environ.setdefault("DRY_RUN", "true")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

sys.path.insert(0, os.path.dirname(__file__))

_SPEC = importlib.util.spec_from_file_location(
    "appsync_feed_publisher_live_event_fields_s97_0b",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
mod = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(mod)


NEW_FIELDS = {
    "recordCreatedAt": "created_at",
    "recordParent": "parent",
    "recordFirstCheckedOutAt": "first_checked_out_at",
    "recordClosedAt": "closed_at",
    "recordWave": "wave",
}

VALUES = {
    "created_at": "2026-11-01T08:00:00Z",
    "parent": "ENC-PLN-108",
    "first_checked_out_at": "2026-11-02T09:30:00Z",
    "closed_at": "2026-11-03T17:45:00Z",
    "wave": "W2",
}

# The v2 key set an older-kit consumer was written against (ENC-TSK-R54-0C): v1 keys plus the
# v2 display fields. See frontend/ui-v2/src/types/feedEvents.ts (FeedRealtimeEvent) and the
# governance dictionary entry appsync_feed.event ("Clients must ignore unknown keys").
OLD_KIT_KEYS = {
    "eventId", "recordId", "record_type", "action", "actorType", "actorId", "summary", "cursor",
    "channels", "schemaVersion", "recordTitle", "recordStatus", "recordPriority",
    "recordUpdatedAt", "recordVersionSeq",
}


def _typed(image: dict) -> dict:
    out = {}
    for k, v in image.items():
        if isinstance(v, bool):
            out[k] = {"BOOL": v}
        elif isinstance(v, (int, float)):
            out[k] = {"N": str(v)}
        elif isinstance(v, dict):
            out[k] = {"M": _typed(v)}
        else:
            out[k] = {"S": str(v)}
    return out


def _record(event_name: str = "MODIFY", **extra) -> dict:
    image = {
        "record_id": "task#ENC-TSK-S97-0B",
        "item_id": "ENC-TSK-S97-0B",
        "record_type": "task",
        "project_id": "enceladus",
        "title": "Plans W2.2 live event fields",
        "status": "in-progress",
        "priority": "P2",
        "updated_at": "2026-11-19T01:02:03Z",
        "version_seq": 77,
        "write_source": {"provider": "ENC-SES-0NW", "channel": "mcp_server"},
    }
    image.update(extra)
    ddb = {
        "SequenceNumber": "seq-1",
        "ApproximateCreationDateTime": 1_700_000_000.0,
        "NewImage" if event_name != "REMOVE" else "OldImage": _typed(image),
    }
    return {"eventName": event_name, "eventID": "seq-1", "dynamodb": ddb}


def _payload(**extra) -> dict:
    p = mod.build_event_payload(_record(**extra), 0)
    assert p is not None
    return p


def test_field_map_is_exactly_the_five_documented_fields():
    assert dict(mod.LIVE_EVENT_OPTIONAL_FIELDS) == NEW_FIELDS


def test_record_with_all_five_values_carries_all_five():
    p = _payload(**VALUES)
    for payload_key, record_key in NEW_FIELDS.items():
        assert p[payload_key] == VALUES[record_key]
    assert p["schemaVersion"] == 2
    assert set(p) == OLD_KIT_KEYS | set(NEW_FIELDS)


def test_record_with_none_of_the_five_omits_all_five():
    p = _payload()
    assert p["schemaVersion"] == 2
    for payload_key in NEW_FIELDS:
        assert payload_key not in p
    assert set(p) == OLD_KIT_KEYS


@pytest.mark.parametrize("payload_key,record_key", sorted(NEW_FIELDS.items()))
def test_each_field_individually_present(payload_key, record_key):
    p = _payload(**{record_key: VALUES[record_key]})
    assert p[payload_key] == VALUES[record_key]
    assert p["schemaVersion"] == 2
    # only that one new key appears
    assert set(p) - OLD_KIT_KEYS == {payload_key}


@pytest.mark.parametrize("payload_key,record_key", sorted(NEW_FIELDS.items()))
@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_value_is_omitted_not_emitted_empty(payload_key, record_key, blank):
    p = _payload(**{record_key: blank})
    assert payload_key not in p
    assert p["schemaVersion"] == 2


def test_fields_ride_on_update_and_remove_events_too():
    rec = _record("REMOVE", **VALUES)
    p = mod.build_event_payload(rec, 0)
    assert p["action"] == "removed"
    assert p["recordClosedAt"] == VALUES["closed_at"]
    assert p["schemaVersion"] == 2


def test_wave_is_omitted_when_the_record_has_no_wave():
    # ENC-TSK-S96-0F adds the wave attribute in parallel; until a record carries it, no key.
    p = _payload(**{k: v for k, v in VALUES.items() if k != "wave"})
    assert "recordWave" not in p
    assert p["recordParent"] == "ENC-PLN-108"


def test_fields_appear_on_every_channel_publish_but_full_body_path_is_untouched():
    p = _payload(**VALUES)
    assert p["channels"][0] == "/feed/updates"
    # build_full_record_body (per-record channel) still returns the raw image, not these keys.
    body = mod.build_full_record_body(_record(**VALUES))
    assert "recordCreatedAt" not in body and body["created_at"] == VALUES["created_at"]


def test_other_v2_fields_are_unchanged_by_the_additions():
    base = _payload()
    full = _payload(**VALUES)
    for key in OLD_KIT_KEYS - {"eventId"}:
        assert base[key] == full[key], key


def test_fully_populated_event_stays_within_the_existing_hard_ceiling():
    # The suite's v2 ceiling is 1200 B (test_v2_title_truncated_...). The median budget (700 B)
    # is asserted on a minimal image in test_lambda_function.py and is not touched here.
    size = len(json.dumps(_payload(**VALUES), separators=(",", ":")).encode("utf-8"))
    assert size < 1200, size


def test_old_consumer_ignoring_unknown_keys_is_unaffected():
    """AC-2. No version-2 schema or validator exists in the repo (the kit's defensive applier is an
    external @io-kit package; the dictionary entry is prose). So the old consumer is modelled the way
    that contract is written: read only the keys it knew at v2 and ignore the rest."""

    def old_consumer(event: dict) -> dict:
        assert event.get("schemaVersion", 1) in (1, 2)  # old kit applies v1 and v2
        return {k: event[k] for k in OLD_KIT_KEYS if k in event}

    legacy = _payload()
    widened = _payload(**VALUES)
    seen_new, seen_old = old_consumer(widened), old_consumer(legacy)
    seen_new.pop("eventId"), seen_old.pop("eventId")  # time-ordered random id differs per build
    assert seen_new == seen_old
    # round-trips through JSON exactly as it travels over AppSync
    wire = json.loads(json.dumps(widened))
    assert wire["schemaVersion"] == 2
    assert old_consumer(wire)["recordStatus"] == "in-progress"
    assert old_consumer(wire)["recordUpdatedAt"] == "2026-11-19T01:02:03Z"


def test_schema_version_constant_is_not_bumped():
    assert mod.SCHEMA_VERSION == 2
    assert _payload(**VALUES)["schemaVersion"] == 2
    assert _payload()["schemaVersion"] == 2
