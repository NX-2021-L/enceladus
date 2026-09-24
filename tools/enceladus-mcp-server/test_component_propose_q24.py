"""Tests for _component_propose's v3 field forwarding (ENC-TSK-Q24 / ENC-ISS-797).

Before this fix, _component_propose accepted component_address,
component_repo_dir, component_address_class, component_class,
requested_required_transition_type, and required_transition_type_rationale
as caller args but silently dropped them before building the
coordination_api POST /components/propose payload -- a behaviour bug, no
new fields on the wire contract. These tests assert the forwarded payload
now carries all five v3 fields when supplied, plus the rationale, and
omits any that are absent.
"""

import asyncio
import importlib.util
import json
import pathlib
import sys
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_server_component_propose_q24", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _call_component_propose(args: dict) -> dict:
    content = _run(server._component_propose(args))
    assert content, "component_propose returned empty content"
    return json.loads(content[0].text)


def test_component_propose_forwards_all_v3_fields_when_present():
    captured = []

    def fake_request(method, path, payload=None, query=None):
        captured.append((method, path, dict(payload) if payload else {}))
        return {"success": True, "component_id": "comp-1"}

    with patch.object(server, "_require_governance_hash", return_value=None), \
         patch.object(server, "_coordination_api_request", side_effect=fake_request):
        _call_component_propose(
            {
                "component_id": "comp-1",
                "display_name": "Comp One",
                "project_id": "enceladus",
                "governance_hash": "test-hash",
                "component_address": "backend/lambda/comp_one",
                "component_repo_dir": "backend/lambda/comp_one",
                "component_address_class": "lambda",
                "component_class": "service",
                "requested_required_transition_type": "code_only",
                "required_transition_type_rationale": "pure backend change, no docs impact",
            }
        )

    assert len(captured) == 1
    method, path, payload = captured[0]
    assert method == "POST"
    assert path == "/components/propose"
    assert payload["component_address"] == "backend/lambda/comp_one"
    assert payload["component_repo_dir"] == "backend/lambda/comp_one"
    assert payload["component_address_class"] == "lambda"
    assert payload["component_class"] == "service"
    assert payload["requested_required_transition_type"] == "code_only"
    assert payload["required_transition_type_rationale"] == "pure backend change, no docs impact"


def test_component_propose_omits_absent_v3_fields():
    captured = []

    def fake_request(method, path, payload=None, query=None):
        captured.append(dict(payload) if payload else {})
        return {"success": True, "component_id": "comp-2"}

    with patch.object(server, "_require_governance_hash", return_value=None), \
         patch.object(server, "_coordination_api_request", side_effect=fake_request):
        _call_component_propose(
            {
                "component_id": "comp-2",
                "display_name": "Comp Two",
                "project_id": "enceladus",
                "governance_hash": "test-hash",
            }
        )

    assert len(captured) == 1
    payload = captured[0]
    for key in (
        "component_address",
        "component_repo_dir",
        "component_address_class",
        "component_class",
        "requested_required_transition_type",
        "required_transition_type_rationale",
    ):
        assert key not in payload


if __name__ == "__main__":
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
