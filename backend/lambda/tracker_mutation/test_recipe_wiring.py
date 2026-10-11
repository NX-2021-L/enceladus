"""DVP-TSK-968 part A: Lambda wiring of the recipe service (ids, internal producer principal, routes)."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import test_escalation_gate_e4 as gate  # noqa: E402
import test_recipe_service as svc  # noqa: E402


def _tm():
    for mod in list(sys.modules.values()):
        f = str(getattr(mod, "__file__", "") or "")
        if f.endswith(os.path.join("tracker_mutation", "lambda_function.py")) and hasattr(mod, "_handle_escalation_produce"):
            return mod
    import importlib.util
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    spec = importlib.util.spec_from_file_location("tracker_mutation_recipe_wiring",
                                                  os.path.join(os.path.dirname(__file__), "lambda_function.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


tm = _tm()


def test_record_types_are_minted_in_the_suffix_maps():
    assert tm._TRACKER_TYPE_SUFFIX["recipe"] == "REC" and tm._TRACKER_TYPE_SUFFIX["recipe_run"] == "RUN"
    assert tm._ID_SEGMENT_TO_TYPE["REC"] == "recipe" and tm._ID_SEGMENT_TO_TYPE["RUN"] == "recipe_run"
    assert len(set(tm._TRACKER_TYPE_SUFFIX.values())) == len(tm._TRACKER_TYPE_SUFFIX)


def test_recipe_runner_principal_is_internal_only(monkeypatch):
    monkeypatch.delenv("GATE_PRODUCER_PRINCIPALS", raising=False)
    src, err = tm._gate_resolve_producer("recipe-runner", None)
    assert src is None and err
    token = tm._INTERNAL_PRODUCER.set("recipe-runner")
    try:
        assert tm._gate_resolve_producer("recipe-runner", None) == ("recipe", None)
    finally:
        tm._INTERNAL_PRODUCER.reset(token)
    resp = tm._handle_escalation_produce("devops", {"source_principal": "recipe-runner", "kind": "acceptance"})
    assert resp["statusCode"] == 403          # an HTTP caller cannot claim the internal principal


def test_ddb_roundtrip_keeps_structured_fields_and_numbers():
    item = {"record_id": "recipe#DVP-REC-001@1.0.0", "item_id": "DVP-REC-001@1.0.0", "record_kind": "version",
            "definition": {"steps": [{"id": "a"}]}, "validation": None, "history": [{"actor": "x"}], "rev": 3,
            "status": "draft", "tags": ["t"]}
    raw = tm._recipe_to_ddb(dict(item, project_id="devops"))
    assert raw["project_id"] == {"S": "devops"} and "validation" not in raw
    back = tm._recipe_from_ddb(raw)
    assert back["definition"] == item["definition"] and back["history"] == item["history"] and back["tags"] == ["t"]
    assert int(back["rev"]) == 3 and back["status"] == "draft"


@pytest.mark.parametrize("path,sub", [
    ("/api/v1/tracker/devops/recipe", None), ("/devops/recipe/list", None), ("/api/v1/tracker/devops/recipe/DVP-REC-001", None),
    ("/api/v1/tracker/devops/recipe/DVP-REC-001/validate", "validate"),
    ("/api/v1/tracker/devops/recipe/DVP-REC-001/publish-request", "publish-request"),
    ("/api/v1/tracker/devops/recipe/DVP-REC-001/apply", "apply")])
def test_route_regex(path, sub):
    m = tm._RE_RECIPE.match(path)
    assert m and m.group("project") == "devops" and m.group("sub") == sub
    assert tm._RE_RECIPE.match("/api/v1/tracker/devops/recipe/DVP-REC-001/other") is None


def _event(method, path, body=None, query=None):
    return {"httpMethod": method, "rawPath": path, "body": json.dumps(body) if body is not None else None,
            "queryStringParameters": query}


def test_http_flow_create_validate_publish_request_apply(monkeypatch):
    st, ctx = svc.make()
    monkeypatch.setattr(tm, "_authenticate", lambda e, s=None: ({"sub": "agent"}, None))
    monkeypatch.setattr(tm, "_validate_project_exists", lambda p: None)
    monkeypatch.setattr(tm, "_normalize_write_source", lambda b, c: b.setdefault("write_source", {"provider": "agent-1"}))
    monkeypatch.setattr(tm, "_recipe_context", lambda: ctx)
    base = "/api/v1/tracker/devops/recipe"
    r = tm.lambda_handler(_event("POST", base, svc.body(dry_run=True)), None)
    assert r["statusCode"] == 200 and json.loads(r["body"])["recipe_id"] is None and st.puts == 0
    r = tm.lambda_handler(_event("POST", base, svc.body()), None)
    assert r["statusCode"] == 201 and json.loads(r["body"])["recipe_id"] == "DVP-REC-001"
    r = tm.lambda_handler(_event("POST", base + "/DVP-REC-001/validate", {"version": "1.0.0"}), None)
    assert json.loads(r["body"])["status"] == "validated"
    r = tm.lambda_handler(_event("POST", base + "/DVP-REC-001/publish-request", {"version": "1.0.0", "rationale": "go"}), None)
    assert r["statusCode"] == 202
    eid = json.loads(r["body"])["escalation_id"]
    r = tm.lambda_handler(_event("POST", base + "/DVP-REC-001/apply", {"escalation_id": eid}), None)
    assert r["statusCode"] == 409 and json.loads(r["body"])["status"] == "failed"
    st.esc[eid]["status"] = "approved"
    r = tm.lambda_handler(_event("POST", base + "/DVP-REC-001/apply", {"escalation_id": eid}), None)
    out = json.loads(r["body"])
    assert r["statusCode"] == 200 and out["status"] == "applied" and out["result"]["status"] == "published"
    r = tm.lambda_handler(_event("GET", base + "/list", query={"status": "published"}), None)
    assert json.loads(r["body"])["count"] == 1
    r = tm.lambda_handler(_event("GET", base + "/DVP-REC-001"), None)
    assert json.loads(r["body"])["version"]["status"] == "published"
