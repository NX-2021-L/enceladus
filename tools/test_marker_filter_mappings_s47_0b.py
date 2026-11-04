"""ENC-TSK-S47-0B: every graph-sync / feed projection event-source mapping filters out marker-only
MODIFYs (write_kind=marker) while still passing legacy items (no write_kind) and REMOVE events.

Hermetic: parses the CloudFormation YAML (no AWS). Run: python3 -m pytest tools/test_marker_filter_mappings_s47_0b.py -q
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

CFN = Path(__file__).resolve().parents[1] / "infrastructure" / "cloudformation"
ANYTHING_BUT = {"anything-but": ["marker"]}
NOT_EXISTS = {"exists": False}  # lives at write_kind.S: exists:false on the non-leaf write_kind matches EVERYTHING


def _load(name: str) -> dict:
    class L(yaml.SafeLoader):
        pass

    def _tag(loader, suffix, node):  # CFN intrinsic tags (!Ref, !Sub, ...) -> opaque
        return None

    L.add_multi_constructor("!", _tag)
    return yaml.load((CFN / name).read_text(), Loader=L)["Resources"]


def _patterns(res: dict) -> list:
    return [json.loads(f["Pattern"]) for f in res["Properties"]["FilterCriteria"]["Filters"]]


def _dig(d, path):
    for k in path:
        d = d[k]
    return d


def _assert_marker_filters(patterns: list, prefix: tuple, name: str) -> None:
    anything_but = [p for p in patterns if _has(p, prefix + ("write_kind", "S"), [ANYTHING_BUT])]
    not_exists = [p for p in patterns if _has(p, prefix + ("write_kind", "S"), [NOT_EXISTS])]
    assert len(anything_but) == 1, f"{name}: want exactly one anything-but-marker filter, got {patterns}"
    assert len(not_exists) == 1, f"{name}: want exactly one write_kind exists:false filter, got {patterns}"
    assert len(patterns) <= 5, f"{name}: Lambda allows at most 5 filters"


def _has(p, path, want) -> bool:
    try:
        return _dig(p, path) == want
    except (KeyError, TypeError):
        return False


def test_graph_sync_tracker_stream_mapping():
    pats = _patterns(_load("02-compute.yaml")["GraphSyncTrackerStreamTrigger"])
    _assert_marker_filters(pats, ("dynamodb", "NewImage"), "GraphSyncTrackerStreamTrigger")
    for p in pats:
        if p.get("eventName") == ["INSERT", "MODIFY"]:  # the pre-existing record_type scoping is preserved
            assert p["dynamodb"]["NewImage"]["record_type"] == {"S": [{"anything-but": "reference"}]}
    assert any(p.get("eventName") == ["REMOVE"] for p in pats), "REMOVE filter must be kept"


def test_graph_sync_documents_stream_mapping():
    pats = _patterns(_load("02-compute.yaml")["GraphSyncDocumentsStreamTrigger"])
    _assert_marker_filters(pats, ("dynamodb", "NewImage"), "GraphSyncDocumentsStreamTrigger")
    assert any(p.get("eventName") == ["REMOVE"] for p in pats), "REMOVE filter must be kept"


def test_sqs_fifo_mappings_filter_on_body():
    res = _load("02-compute.yaml")
    for name in ("GraphSyncSqsTrigger", "FeedPublisherSqsTrigger"):
        pats = _patterns(res[name])
        _assert_marker_filters(pats, ("body", "dynamodb", "NewImage"), name)
        assert any(_has(p, ("body", "eventName"), ["REMOVE"]) for p in pats), f"{name}: REMOVE must pass"


def test_appsync_feed_stream_mappings():
    res = _load("06-appsync-events.yaml")
    pats = _patterns(res["AppSyncFeedTrackerStreamTrigger"])
    _assert_marker_filters(pats, ("dynamodb", "NewImage"), "AppSyncFeedTrackerStreamTrigger")
    assert any(p.get("eventName") == ["REMOVE"] for p in pats)
    dpats = _patterns(res["AppSyncFeedDocumentsStreamTrigger"])
    _assert_marker_filters(dpats, ("dynamodb", "NewImage"), "AppSyncFeedDocumentsStreamTrigger")
    for p in dpats:  # the counter-row exclusion is preserved on every branch
        assert p["dynamodb"]["Keys"]["document_id"]["S"] == [{"anything-but": ["__COUNTER__VERSION_SEQ__"]}]
    assert any(p.get("eventName") == ["REMOVE"] for p in dpats)


def test_pipes_untouched():
    """The ENC-TSK-Q22 gate refuses Pipe SourceParameters edits: no Pipe filter may mention write_kind."""
    res = _load("02-compute.yaml")
    for name, r in res.items():
        if r.get("Type") == "AWS::Pipes::Pipe":
            assert "write_kind" not in json.dumps(r["Properties"].get("SourceParameters")), name


# ---- semantic check: a minimal EventBridge matcher (verified against events:TestEventPattern) ----
def _leaf_ok(rule, value, present) -> bool:
    for r in rule:
        if isinstance(r, dict) and r.get("exists") is False:
            if not present:
                return True
        elif isinstance(r, dict) and "anything-but" in r:
            ab = r["anything-but"]
            ab = ab if isinstance(ab, list) else [ab]
            if present and value not in ab:
                return True
        elif present and value == r:
            return True
    return False


def _match(pattern, event) -> bool:
    for k, rule in pattern.items():
        if isinstance(rule, dict):
            sub = event.get(k) if isinstance(event, dict) else None
            if not _match(rule, sub if isinstance(sub, dict) else {}):
                return False
        else:
            present = isinstance(event, dict) and k in event and not isinstance(event[k], dict)
            if not _leaf_ok(rule, event.get(k) if present else None, present):
                return False
    return True


def _image_event(write_kind, event_name="MODIFY"):
    img = {"record_type": {"S": "task"}}
    if write_kind:
        img["write_kind"] = {"S": write_kind}
    return {"eventName": event_name, "dynamodb": {"NewImage": img}}


def _passes(pats, event, wrap=None) -> bool:
    ev = {wrap: event} if wrap else event
    return any(_match(p, ev) for p in pats)


def test_filter_semantics_governed_and_legacy_pass_marker_drops():
    res = _load("02-compute.yaml")
    cases = [("GraphSyncTrackerStreamTrigger", None), ("GraphSyncDocumentsStreamTrigger", None),
             ("GraphSyncSqsTrigger", "body"), ("FeedPublisherSqsTrigger", "body")]
    for name, wrap in cases:
        pats = _patterns(res[name])
        assert _passes(pats, _image_event("governed"), wrap), name
        assert _passes(pats, _image_event(None), wrap), f"{name}: legacy item without write_kind must pass"
        assert not _passes(pats, _image_event("marker"), wrap), f"{name}: marker must be dropped"
    for name in ("AppSyncFeedTrackerStreamTrigger",):
        pats = _patterns(_load("06-appsync-events.yaml")[name])
        assert _passes(pats, _image_event("governed")) and _passes(pats, _image_event(None))
        assert not _passes(pats, _image_event("marker"))
