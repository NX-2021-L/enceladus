"""ENC-TSK-Q14-0D (O2.4): census payload assembly + schema fixture.

Drives _handle_list_census end-to-end (mode=census dispatch included) and
validates the response body against tests/fixtures/census_v1.schema.json
with a minimal hand-rolled JSON Schema validator (jsonschema is not a
tracker_mutation test dependency -- see requirements.txt).
"""
import json
import os
import unittest
from unittest import mock

from fake_ddb_paging import PagingTable

_SCHEMA_PATH = os.path.join(
    os.path.dirname(__file__), "tests", "fixtures", "census_v1.schema.json",
)


def _load_schema():
    with open(_SCHEMA_PATH) as fh:
        return json.load(fh)


def _validate(instance, schema, root=None, path="$"):
    """Minimal JSON Schema (draft-07 subset) validator.

    Supports: type (str or list), properties/required/additionalProperties,
    items, const, enum, minimum/maximum, and local $ref (#/definitions/X).
    Raises AssertionError with a path-qualified message on the first
    mismatch -- enough to cover census_v1.schema.json without pulling in
    the `jsonschema` package (not a tracker_mutation test dependency).
    """
    root = root if root is not None else schema

    if "$ref" in schema:
        ref = schema["$ref"]
        assert ref.startswith("#/"), f"{path}: only local $refs supported, got {ref!r}"
        target = root
        for part in ref[2:].split("/"):
            target = target[part]
        _validate(instance, target, root, path)
        return

    if "const" in schema:
        assert instance == schema["const"], f"{path}: expected const {schema['const']!r}, got {instance!r}"

    if "enum" in schema:
        assert instance in schema["enum"], f"{path}: {instance!r} not in enum {schema['enum']!r}"

    json_type_map = {
        "string": str, "integer": int, "number": (int, float),
        "boolean": bool, "array": list, "object": dict, "null": type(None),
    }
    schema_type = schema.get("type")
    if schema_type is not None:
        allowed = schema_type if isinstance(schema_type, list) else [schema_type]
        py_types = tuple(json_type_map[t] for t in allowed)
        # bool is a subclass of int in Python -- only accept bool for an
        # explicit "boolean" schema type, never silently as an "integer".
        if isinstance(instance, bool) and bool not in py_types:
            raise AssertionError(f"{path}: expected type(s) {allowed}, got bool")
        assert isinstance(instance, py_types), f"{path}: expected type(s) {allowed}, got {type(instance).__name__}"

    if schema_type == "integer" or (isinstance(schema_type, list) and "integer" in schema_type):
        if "minimum" in schema and isinstance(instance, int):
            assert instance >= schema["minimum"], f"{path}: {instance} < minimum {schema['minimum']}"
        if "maximum" in schema and isinstance(instance, int):
            assert instance <= schema["maximum"], f"{path}: {instance} > maximum {schema['maximum']}"

    if schema_type == "object" and isinstance(instance, dict):
        properties = schema.get("properties", {})
        for req in schema.get("required", []):
            assert req in instance, f"{path}: missing required property {req!r}"
        if schema.get("additionalProperties") is False:
            extra = set(instance.keys()) - set(properties.keys())
            assert not extra, f"{path}: unexpected properties {sorted(extra)}"
        addl_schema = schema.get("additionalProperties")
        for key, val in instance.items():
            if key in properties:
                _validate(val, properties[key], root, f"{path}.{key}")
            elif isinstance(addl_schema, dict):
                _validate(val, addl_schema, root, f"{path}.{key}")

    if schema_type == "array" and isinstance(instance, list):
        items_schema = schema.get("items")
        if items_schema:
            for idx, item in enumerate(instance):
                _validate(item, items_schema, root, f"{path}[{idx}]")


def _raw_item(n, project_id="proj", record_type="task", status="open"):
    item_id = f"ENC-TSK-{n:04d}"
    return {
        "project_id": {"S": project_id},
        "record_id": {"S": f"{record_type}#{item_id}"},
        "item_id": {"S": item_id},
        "record_type": {"S": record_type},
        "status": {"S": status},
        "title": {"S": f"Task {n}"},
        "updated_at": {"S": f"2026-09-{(n % 28) + 1:02d}T00:00:00Z"},
    }


def _escalation_item(n, project_id="proj", status=None):
    item = {"project_id": {"S": project_id}, "record_id": {"S": f"escalation#ENC-ESC-{n:04d}"}}
    if status is not None:
        item["status"] = {"S": status}
    return item


class TestCensusPayloadSchema(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self.schema = _load_schema()

    def _call(self, query_params, primary_items, escalation_items=None):
        primary_table = PagingTable(primary_items, raw_page_size=200)
        tables = [primary_table]
        if escalation_items is not None:
            tables.append(PagingTable(escalation_items, raw_page_size=200))
        with mock.patch.object(self.lf, "_get_ddb", side_effect=tables):
            resp = self.lf._handle_list_records("proj", query_params)
        return resp, json.loads(resp["body"])

    def test_mode_census_dispatches_and_validates_against_schema(self):
        items = [_raw_item(n) for n in range(1, 71)]
        resp, body = self._call(
            {"mode": "census", "type": "task", "page_size": "50"}, items,
        )
        self.assertEqual(resp["statusCode"], 200)
        _validate(body, self.schema)
        self.assertNotIn("records", body, "census payload never carries a records key")
        self.assertEqual(body["ids_inline_cap"], 500)
        self.assertEqual(body["order"], "unspecified", "typed GSI branch -- D6")

    def test_base_branch_order_record_id_asc(self):
        items = [_raw_item(n) for n in range(1, 6)]
        resp, body = self._call({"mode": "census"}, items, escalation_items=[])
        self.assertEqual(resp["statusCode"], 200)
        _validate(body, self.schema)
        self.assertEqual(body["order"], "record_id_asc", "untyped base-table branch -- D6")

    def test_ids_present_at_count_500_absent_at_501(self):
        items_500 = [_raw_item(n) for n in range(1, 501)]
        _, body_500 = self._call({"mode": "census", "type": "task"}, items_500)
        _validate(body_500, self.schema)
        self.assertEqual(body_500["count"], 500)
        self.assertIn("ids", body_500)
        self.assertEqual(len(body_500["ids"]), 500)

        items_501 = [_raw_item(n) for n in range(1, 502)]
        _, body_501 = self._call({"mode": "census", "type": "task"}, items_501)
        _validate(body_501, self.schema)
        self.assertEqual(body_501["count"], 501)
        self.assertNotIn("ids", body_501)

    def test_ids_and_page_anchors_are_item_ids_not_raw_record_ids(self):
        """ENC-TSK-Q27: the live defect -- `ids` and `pages[].first/last.id`
        must be item ids ('ENC-TSK-0001'), never the raw DynamoDB sort key
        ('task#ENC-TSK-0001')."""
        items = [_raw_item(n) for n in range(1, 11)]
        resp, body = self._call({"mode": "census", "type": "task"}, items)
        self.assertEqual(resp["statusCode"], 200)
        _validate(body, self.schema)

        expected_ids = {f"ENC-TSK-{n:04d}" for n in range(1, 11)}
        self.assertEqual(set(body["ids"]), expected_ids)
        for raw_id in body["ids"]:
            self.assertFalse(raw_id.startswith("task#"), f"leaked raw record_id: {raw_id!r}")

        for page in body["pages"]:
            for anchor in (page["first"], page["last"]):
                self.assertIn(anchor["id"], expected_ids)
                self.assertFalse(anchor["id"].startswith("task#"))

    def test_unknown_mode_is_400_not_a_silent_plain_list(self):
        with mock.patch.object(self.lf, "_get_ddb", return_value=PagingTable([], raw_page_size=200)):
            resp = self.lf._handle_list_records("proj", {"mode": "bogus"})
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertFalse(body["success"])
        self.assertNotIn("records", body)

    def test_status_filter_applies_inside_the_walk(self):
        items = [_raw_item(n, status="closed") for n in range(1, 6)] + [
            _raw_item(6, status="open"),
        ]
        resp, body = self._call(
            {"mode": "census", "type": "task", "status": "open"}, items,
        )
        self.assertEqual(resp["statusCode"], 200)
        _validate(body, self.schema)
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["by_type"], {"task": 1})

    def test_status_filter_applies_to_escalation_walk_too(self):
        """Review fix (ENC-TSK-Q14-0C): a mixed (no `type`) census with a
        `status` filter must apply inside the escalation walk exactly as
        it applies inside the primary walk, not just the primary one.

        Repro from the review finding: 3 open + 2 closed tasks, 4 open +
        6 resolved escalations, status=open -> expected count is
        3 tasks + 4 escalations = 7, not 3 tasks + all 10 escalations.
        """
        items = [_raw_item(n, status="open") for n in range(1, 4)] + [
            _raw_item(n, status="closed") for n in range(4, 6)
        ]
        escalation_items = [_escalation_item(n, status="open") for n in range(1, 5)] + [
            _escalation_item(n, status="resolved") for n in range(5, 11)
        ]
        resp, body = self._call(
            {"mode": "census", "status": "open"}, items, escalation_items=escalation_items,
        )
        self.assertEqual(resp["statusCode"], 200)
        _validate(body, self.schema)
        self.assertEqual(body["by_type"], {"task": 3, "escalation": 4})
        self.assertEqual(body["count"], 7)


if __name__ == "__main__":
    unittest.main()
