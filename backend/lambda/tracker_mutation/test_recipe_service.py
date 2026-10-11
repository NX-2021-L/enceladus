"""DVP-TSK-968 part A: recipe primitive service (entities, hashing, lifecycle, gates, dry_run)."""
import copy
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import recipe_service as rs  # noqa: E402

NOW = "2026-10-11T12:00:00Z"
REGISTRY = {"enceladus": {"tracker.create", "tracker.set"}, "io-finance": {"finance.categorize"}}
P = "devops"


class Store:
    def __init__(self):
        self.items, self.puts, self.minted, self.escalations, self.esc = {}, 0, 0, [], {}
        self.active = 0

    def get(self, p, sk):
        return copy.deepcopy(self.items.get((p, sk)))

    def put(self, p, item, if_absent=False, expect=None):
        key, cur = (p, item["record_id"]), self.items.get((p, item["record_id"]))
        if if_absent and cur is not None:
            return False
        if expect and (cur is None or cur.get(expect[0]) != expect[1]):
            return False
        self.puts += 1
        self.items[key] = copy.deepcopy(item)
        return True

    def query(self, p, prefix):
        return [copy.deepcopy(v) for (pp, sk), v in sorted(self.items.items()) if pp == p and sk.startswith(prefix)]

    def mint(self, p):
        self.minted += 1
        return f"DVP-REC-{self.minted:03d}"

    def escalate(self, p, body):
        self.escalations.append(body)
        eid = f"DVP-ESC-{len(self.escalations):03d}"
        self.esc[eid] = {"escalation_id": eid, "status": "requested", "subject": body["subject"],
                         "sourcePrincipal": body["source_principal"]}
        return 201, {"escalation_id": eid}

    def escalation(self, p, eid):
        return copy.deepcopy(self.esc.get(eid))


def make(registry=REGISTRY):
    st = Store()
    ctx = rs.RecipeContext(get=st.get, put=st.put, query=st.query, mint=st.mint, now=lambda: NOW,
                           registry=lambda: registry, escalate=st.escalate, escalation=st.escalation,
                           active_runs=lambda p, r, v: st.active)
    return st, ctx


def defn():
    return {
        "description": "close a statement",
        "inputs": {"type": "object", "required": ["statement_id"], "additionalProperties": False,
                   "properties": {"statement_id": {"type": "string", "pattern": "^STM-[0-9]+$"},
                                  "auto_categorize": {"type": "boolean", "default": False}}},
        "steps": [
            {"id": "create", "action": "tracker.create", "arguments": {"title": "$inputs.statement_id"},
             "compensate": {"action": "tracker.set", "arguments": {"record_id": "$create.record_id"}}},
            {"id": "approve", "type": "gate",
             "gate": {"prompt": "ok?", "escalation_kind": "acceptance", "timeout": {"seconds": 3600},
                      "inputs": {"type": "object", "properties": {"note": {"type": "string"}}}}},
            {"id": "finish", "action": "finance.categorize", "surface": "io-finance",
             "arguments": {"stmt": "$inputs.statement_id", "note": "$approve.inputs.note", "rid": "$create.record_id"}},
        ],
        "tools": ["finance.categorize", "tracker.create", "tracker.set"],
        "outputs": {"schema": {"type": "object", "required": ["record_id"], "properties": {"record_id": {"type": "string"}}},
                    "from": {"record_id": "$create.record_id"}},
        "surfaces": ["enceladus", "io-finance"],
    }


def body(**kw):
    b = {"name": "daily-close", "project_ids": ["finance"], "definition": defn(), "tags": ["finance"]}
    b.update(kw)
    return b


def published(ctx, st, rec=None, name="daily-close"):
    if rec is None:
        code, out = rs.create(ctx, P, body(name=name), "agent-1")
        rec = out["recipe_id"]
    ver = "1.0.0"
    assert rs.validate(ctx, P, {"recipe_id": rec, "version": ver}, "agent-1")[1]["status"] == "validated"
    code, gate = rs.publish_request(ctx, P, {"recipe_id": rec, "version": ver, "rationale": "ready"}, "agent-1")
    assert code == 202
    st.esc[gate["escalation_id"]]["status"] = "approved"
    code, res = rs.apply_decision(ctx, P, rec, {"escalation_id": gate["escalation_id"], "decider": "io"}, "io")
    assert code == 200 and res["status"] == "published"
    return rec, ver, gate["escalation_id"]


def codes(definition, registry=REGISTRY):
    return {e["code"] for e in rs.validate_definition(definition, registry)}


def test_create_mints_id_and_hash_is_stable_and_order_independent():
    st, ctx = make()
    code, out = rs.create(ctx, P, body(), "agent-1")
    assert code == 201 and out["recipe_id"] == "DVP-REC-001" and out["version"] == "1.0.0" and out["status"] == "draft"
    assert len(out["content_hash"]) == 71 and out["content_hash"].startswith("sha256:")
    reordered = json.loads(json.dumps(defn(), sort_keys=True))
    assert rs.compute_content_hash("daily-close", "1.0.0", reordered) == out["content_hash"]
    assert rs.compute_content_hash("daily-close", "1.0.1", reordered) != out["content_hash"]
    head = st.get(P, "recipe#DVP-REC-001")
    assert head["project_ids"] == ["devops", "finance"] and head["owner"] == "agent-1" and head["latest_published"] is None
    assert head["history"][0]["action"] == "create"
    assert st.get(P, "recipe#DVP-REC-001@1.0.0")["status"] == "draft"


def test_name_unique_immutable_and_validation_errors():
    st, ctx = make()
    rs.create(ctx, P, body(), "a")
    assert rs.create(ctx, P, body(), "a")[0] == 409
    code, out = rs.create(ctx, P, body(name="Bad Name"), "a")
    assert code == 400 and out["error_code"] == "VALIDATION_FAILED"
    assert rs.create(ctx, P, body(recipe_id="DVP-REC-001", name="other-name"), "a")[0] == 400
    assert rs.create(ctx, P, {"name": "x-ok-name", "definition": defn()}, "a")[0] == 400   # project_ids required


def test_draft_replace_new_version_and_published_is_immutable():
    st, ctx = make()
    _, first = rs.create(ctx, P, body(), "a")
    d2 = defn(); d2["description"] = "edited"
    code, again = rs.create(ctx, P, body(recipe_id=first["recipe_id"], definition=d2), "a")
    assert code == 200 and again["version"] == "1.0.0" and again["replaced_draft"] and again["content_hash"] != first["content_hash"]
    assert st.minted == 1
    rec, ver, _ = published(ctx, st, rec=first["recipe_id"])
    assert rs.create(ctx, P, body(recipe_id=rec, version="1.0.0"), "a")[1]["error_code"] == "ILLEGAL_TRANSITION"
    d3 = defn(); d3["description"] = "patch change"
    code, nxt = rs.create(ctx, P, body(recipe_id=rec, definition=d3), "a")
    assert code == 201 and nxt["version"] == "1.0.1"
    assert st.get(P, f"recipe#{rec}@1.0.1")["supersedes"] == "1.0.0"
    d4 = defn(); d4["steps"] = d4["steps"][:2]; d4["tools"] = ["tracker.create", "tracker.set"]
    assert rs.create(ctx, P, body(recipe_id=rec, definition=d4), "a")[1]["version"] == "1.0.1"   # replaces the open draft
    assert rs.classify_bump(defn(), d4) == "major"


def test_editing_validated_returns_to_draft_and_clears_validation():
    st, ctx = make()
    _, out = rs.create(ctx, P, body(), "a")
    rs.validate(ctx, P, {"recipe_id": out["recipe_id"], "version": "1.0.0"}, "a")
    assert st.get(P, "recipe#DVP-REC-001@1.0.0")["status"] == "validated"
    d2 = defn(); d2["description"] = "again"
    assert rs.create(ctx, P, body(recipe_id="DVP-REC-001", definition=d2), "stranger")[0] == 403   # not owner
    assert rs.create(ctx, P, body(recipe_id="DVP-REC-001", definition=d2), "a")[0] == 200
    item = st.get(P, "recipe#DVP-REC-001@1.0.0")
    assert item["status"] == "draft" and item["validation"] is None


def test_validate_pass_moves_to_validated():
    st, ctx = make()
    _, out = rs.create(ctx, P, body(), "a")
    code, res = rs.validate(ctx, P, {"recipe_id": out["recipe_id"], "version": "1.0.0", "governance_hash": "gh"}, "a")
    assert code == 200 and res["ok"] and res["errors"] == [] and res["status"] == "validated"
    assert st.get(P, "recipe#DVP-REC-001@1.0.0")["validation"]["governance_hash"] == "gh"
    assert res["validation"]["registry_version"].startswith("sha256:")


@pytest.mark.parametrize("mutate,expected", [
    (lambda d: d["steps"][0].update(action="tracker.nope"), "UNKNOWN_ACTION"),
    (lambda d: d["steps"][0]["arguments"].update(x="$finish.out"), "FORWARD_REFERENCE"),
    (lambda d: d["steps"][0]["arguments"].update(x="$ghost.out"), "UNKNOWN_BINDING_ROOT"),
    (lambda d: d["steps"][0]["arguments"].update(x="$inputs.missing"), "UNKNOWN_INPUT"),
    (lambda d: d["steps"][0]["arguments"].update(x="$inputs..bad"), "BINDING_MALFORMED"),
    (lambda d: d["steps"][2]["arguments"].update(x="$approve.inputs.nope"), "BINDING_UNRESOLVED"),
    (lambda d: d["steps"][2]["arguments"].update(x="$create.record_id/ok"), "BINDING_MALFORMED"),
    (lambda d: d.update(tools=["tracker.create"]), "TOOLS_MISMATCH"),
    (lambda d: d.update(execution="delegated"), "EXECUTION_NOT_SUPPORTED"),
    (lambda d: d["outputs"]["from"].clear(), "OUTPUT_UNBOUND"),
    (lambda d: d["steps"][1].update(id="create"), "STEP_ID_DUPLICATE"),
    (lambda d: d["steps"][1]["gate"].update(escalation_kind="nope"), "GATE_KIND_INVALID"),
    (lambda d: d.update(steps=[]), "STEPS_REQUIRED"),
    (lambda d: d.update(surfaces=["bogus"]), "UNKNOWN_SURFACE"),
    (lambda d: d["inputs"].update(required=["ghost"]), "SCHEMA_INVALID"),
])
def test_validate_definition_failures(mutate, expected):
    d = defn()
    mutate(d)
    got = codes(d)
    if expected is None:
        assert "BINDING_MALFORMED" not in got and "UNKNOWN_BINDING_ROOT" not in got
    else:
        assert expected in got, got
    assert codes(defn()) == set()


def test_failed_validate_keeps_draft_and_missing_registry_fails_closed():
    st, ctx = make()
    bad = defn(); bad["steps"][0]["action"] = "tracker.nope"
    _, out = rs.create(ctx, P, body(definition=bad), "a")
    _, res = rs.validate(ctx, P, {"recipe_id": out["recipe_id"], "version": "1.0.0"}, "a")
    assert res["ok"] is False and res["status"] == "draft"
    st2, ctx2 = make(registry=None)
    _, out2 = rs.create(ctx2, P, body(), "a")
    _, res2 = rs.validate(ctx2, P, {"recipe_id": out2["recipe_id"], "version": "1.0.0"}, "a")
    assert res2["ok"] is False and any(e["code"] == "REGISTRY_UNAVAILABLE" for e in res2["errors"])


def test_publish_request_opens_acceptance_escalation_and_reuses_pending():
    st, ctx = make()
    _, out = rs.create(ctx, P, body(), "a")
    arg = {"recipe_id": out["recipe_id"], "version": "1.0.0", "rationale": "ship it"}
    assert rs.publish_request(ctx, P, arg, "a")[1]["error_code"] == "ILLEGAL_TRANSITION"   # still draft
    rs.validate(ctx, P, {"recipe_id": out["recipe_id"], "version": "1.0.0"}, "a")
    assert rs.publish_request(ctx, P, dict(arg, rationale=""), "a")[0] == 400
    code, gate = rs.publish_request(ctx, P, arg, "a")
    assert code == 202 and gate["escalation_id"] == "DVP-ESC-001" and gate["status"] == "pending"
    req = st.escalations[0]
    assert req["kind"] == "acceptance" and req["source_principal"] == "recipe-runner"
    assert req["subject"] == {"type": "recipe_version", "record_id": out["recipe_id"], "version": "1.0.0",
                              "target": "published", "content_hash": out["content_hash"]}
    assert len(req["proposedCalls"]) == 1 and len(req["proposedCalls"][0]["callHash"]) == 64
    assert st.get(P, "recipe#DVP-REC-001@1.0.0")["publish_escalation_id"] == "DVP-ESC-001"
    again = rs.publish_request(ctx, P, arg, "a")[1]
    assert again["escalation_id"] == "DVP-ESC-001" and again["reused"] and len(st.escalations) == 1
    assert rs.publish_request(ctx, P, dict(arg, content_hash="sha256:" + "0" * 64), "a")[1]["error_code"] == "PIN_MISMATCH"


def test_applier_publishes_only_on_approve_and_binds_exact_version():
    st, ctx = make()
    _, out = rs.create(ctx, P, body(), "a")
    rec = out["recipe_id"]
    rs.validate(ctx, P, {"recipe_id": rec, "version": "1.0.0"}, "a")
    _, gate = rs.publish_request(ctx, P, {"recipe_id": rec, "version": "1.0.0", "rationale": "r"}, "a")
    eid = gate["escalation_id"]
    code, res = rs.apply_decision(ctx, P, rec, {"escalation_id": eid}, "io")        # still pending
    assert code == 409 and res["error_code"] == "NOT_AUTHORIZED"
    assert st.get(P, f"recipe#{rec}@1.0.0")["status"] == "validated"
    assert rs.apply_decision(ctx, P, rec, {"escalation_id": "DVP-ESC-999"}, "io")[0] == 404
    st.esc[eid]["status"] = "approved"
    st.esc[eid]["subject"] = dict(st.esc[eid]["subject"], record_id="DVP-REC-777")
    assert rs.apply_decision(ctx, P, rec, {"escalation_id": eid}, "io")[0] == 403   # names another recipe
    st.esc[eid]["subject"]["record_id"] = rec
    st.esc[eid]["sourcePrincipal"] = "someone"
    assert rs.apply_decision(ctx, P, rec, {"escalation_id": eid}, "io")[0] == 403   # not filed by the service
    st.esc[eid]["sourcePrincipal"] = "recipe-runner"
    code, res = rs.apply_decision(ctx, P, rec, {"escalation_id": eid, "decider": "io-admin"}, "io")
    assert code == 200 and res["status"] == "published"
    item, head = st.get(P, f"recipe#{rec}@1.0.0"), st.get(P, f"recipe#{rec}")
    assert item["status"] == "published" and item["approved_by"] == "io-admin"
    assert head["latest_published"] == "1.0.0" and head["status"] == "published"
    assert rs.apply_decision(ctx, P, rec, {"escalation_id": eid}, "io")[1].get("idempotent") is True
    item["definition"]["description"] = "tampered"
    st.items[(P, f"recipe#{rec}@1.0.0")] = item
    st.items[(P, f"recipe#{rec}@1.0.0")]["status"] = "validated"
    assert rs.apply_decision(ctx, P, rec, {"escalation_id": eid}, "io")[1]["error_code"] == "PIN_MISMATCH"


def test_deprecate_then_retire_is_an_io_gate_with_zero_active_runs():
    st, ctx = make()
    rec, ver, _ = published(ctx, st)
    assert rs.deprecate(ctx, P, {"recipe_id": rec, "version": ver}, "a")[0] == 400           # reason required
    assert rs.deprecate(ctx, P, {"recipe_id": rec, "version": ver, "reason": "old", "replaced_by": "1.1.0"}, "a")[1]["status"] == "deprecated"
    item, head = st.get(P, f"recipe#{rec}@{ver}"), st.get(P, f"recipe#{rec}")
    assert item["deprecation"]["reason"] == "old" and item["deprecation"]["by"] == "a"
    assert head["latest_published"] is None
    assert rs.deprecate(ctx, P, {"recipe_id": rec, "version": ver, "reason": "again"}, "a")[0] == 409
    st.active = 1
    assert rs.deprecate(ctx, P, {"recipe_id": rec, "version": ver, "reason": "x", "target": "retired"}, "a")[0] == 409
    st.active = 0
    code, res = rs.deprecate(ctx, P, {"recipe_id": rec, "version": ver, "reason": "retire", "target": "retired"}, "a")
    assert code == 202 and res["escalation_id"] == "DVP-ESC-002" and res["status"] == "deprecated"
    assert st.escalations[-1]["subject"]["target"] == "retired" and st.get(P, f"recipe#{rec}@{ver}")["status"] == "deprecated"
    st.esc["DVP-ESC-002"]["status"] = "approved"
    st.active = 2
    assert rs.apply_decision(ctx, P, rec, {"escalation_id": "DVP-ESC-002"}, "io")[0] == 409
    st.active = 0
    assert rs.apply_decision(ctx, P, rec, {"escalation_id": "DVP-ESC-002"}, "io")[1]["status"] == "retired"
    assert st.get(P, f"recipe#{rec}@{ver}")["status"] == "retired"


def test_dry_run_performs_zero_writes_mints_nothing_and_nulls_minted_ids():
    st, ctx = make()
    code, out = rs.create(ctx, P, body(), "a", dry_run=True)
    assert code == 200 and out["dry_run"] is True and out["recipe_id"] is None and out["would_do"]["mint"] == "recipe"
    assert st.puts == 0 and st.minted == 0 and not st.items
    _, real = rs.create(ctx, P, body(), "a")
    rec, base = real["recipe_id"], st.puts
    d2 = defn(); d2["description"] = "x"
    assert rs.create(ctx, P, body(recipe_id=rec, definition=d2), "a", dry_run=True)[1]["recipe_id"] == rec
    assert rs.validate(ctx, P, {"recipe_id": rec, "version": "1.0.0"}, "a", dry_run=True)[1]["status"] == "validated"
    assert st.get(P, f"recipe#{rec}@1.0.0")["status"] == "draft"
    rs.validate(ctx, P, {"recipe_id": rec, "version": "1.0.0"}, "a")
    base = st.puts
    code, pr = rs.publish_request(ctx, P, {"recipe_id": rec, "version": "1.0.0", "rationale": "r"}, "a", dry_run=True)
    assert pr["escalation_id"] is None and pr["dry_run"] and "escalation" in pr["would_do"] and not st.escalations
    assert st.puts == base and st.minted == 1
    assert rs.deprecate(ctx, P, {"recipe_id": rec, "version": "1.0.0", "reason": "r"}, "a", dry_run=True)[0] == 409   # not published yet
    assert st.puts == base


def test_get_and_list():
    st, ctx = make()
    _, out = rs.create(ctx, P, body(), "a")
    rec = out["recipe_id"]
    code, res = rs.get(ctx, P, rec)
    assert res["version"] is None and res["resolved"] == "none" and res["versions"][0]["status"] == "draft"
    assert rs.get(ctx, P, rec, "1.0.0")[1]["version"]["definition"]["description"] == "close a statement"
    assert rs.get(ctx, P, "DVP-REC-099")[0] == 404 and rs.get(ctx, P, "nope")[0] == 400
    rec2, ver, _ = published(ctx, st, name="other-recipe")
    assert rs.get(ctx, P, rec2)[1]["version"]["version"] == ver
    _, lst = rs.list_recipes(ctx, P, {})
    assert lst["count"] == 2
    assert rs.list_recipes(ctx, P, {"status": "published"})[1]["count"] == 1
    assert rs.list_recipes(ctx, P, {"tag": "nothing"})[1]["count"] == 0
    assert rs.list_recipes(ctx, P, {"serves_project_id": "finance", "query": "daily"})[1]["count"] >= 1
    assert rs.list_recipes(ctx, P, {"limit": "abc"})[0] == 400


def test_registry_loader_reads_caps_documents(tmp_path):
    (tmp_path / "caps.json").write_text(json.dumps({"actions": [{"name": "a.b"}, {"name": "c.d"}]}))
    (tmp_path / "surfaces").mkdir()
    (tmp_path / "surfaces" / "io-finance.caps.json").write_text(json.dumps({"actions": [{"name": "f.x"}]}))
    reg = rs.load_registry([tmp_path])
    assert reg == {"enceladus": {"a.b", "c.d"}, "io-finance": {"f.x"}}
    assert rs.load_registry([tmp_path / "missing"]) is None
    live = rs.load_registry()      # repo checkout: enceladus caps + the pinned io-finance / io-travel snapshots
    assert live is not None and "recipe.create" in live["enceladus"] and live.get("io-finance") and live.get("io-travel")
