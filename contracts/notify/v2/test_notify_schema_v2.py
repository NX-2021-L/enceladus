"""Conformance tests for notify.schema v2 (ENC-TSK-Q79)."""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

HERE = Path(__file__).parent
SCHEMA = json.loads((HERE / "notify.schema.json").read_text())
FIXTURES = sorted((HERE / "fixtures").glob("*.json"))

EXPECTED_ROUTES = {
    "GET /notifications/vapid-public-key",
    "POST /notifications/subscribe",
    "GET /notifications/devices",
    "GET /notifications/devices/{device_id}/preferences",
    "PUT /notifications/devices/{device_id}/preferences",
    "PATCH /notifications/devices/{device_id}",
    "DELETE /notifications/devices/{device_id}",
    "POST /notifications/devices/{device_id}/test",
}


def _validator(def_name):
    # Validate against a def while resolving local #/$defs refs from the root.
    schema = {"$schema": SCHEMA["$schema"], "$defs": SCHEMA["$defs"], "$ref": f"#/$defs/{def_name}"}
    return Draft202012Validator(schema, format_checker=FormatChecker())


def test_schema_is_valid_draft_2020_12():
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$id"].endswith("notify.schema.v2.json")
    assert SCHEMA["version"] == "2.0.0"


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_fixture(path):
    fx = json.loads(path.read_text())
    v = _validator(fx["def"])
    errors = list(v.iter_errors(fx["body"]))
    if fx["valid"]:
        assert not errors, [e.message for e in errors]
    else:
        assert errors, "invalid fixture unexpectedly validated"


def test_routes_exact():
    assert set(SCHEMA["x-routes"]) == EXPECTED_ROUTES
    assert len(SCHEMA["x-routes"]) == 8
    assert SCHEMA["x-removed"] == [
        "GET /notifications/preferences",
        "PUT /notifications/preferences",
        "DELETE /notifications/subscribe",
    ]
    for spec in SCHEMA["x-routes"].values():
        for ref in (spec["request"], spec["response"]):
            if ref:
                assert ref.removeprefix("#/$defs/") in SCHEMA["$defs"]
