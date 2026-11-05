"""ENC-TSK-S47-0B writer audit: every non-marker write to the tracker / documents tables stamps write_kind.

Why: `write_kind` is STICKY on the item. The projection writers (graph_sync `_mark_source_projected`,
feed_publisher `feed_published_version_seq` claim/release) leave `write_kind = "marker"` behind, and the
Lambda event-source mappings DROP MODIFY records whose NewImage says `marker`. Any later write to that
item that does not set `write_kind = "governed"` in the SAME DynamoDB call would therefore be silently
filtered away from graph / feed / AppSync / audit consumers (no metric can see it). put_item replaces
the whole item, so only a Put that copies a read-back image could re-carry a marker; Puts are stamped
anyway so the rule stays uniform.

Audit classification (backend/lambda/*, DynamoDB write call sites that target the tracker table
`devops-project-tracker` [TRACKER_TABLE / DYNAMODB_TABLE / _CANONICAL_TRACKER_TABLE] or the documents
table [DOCUMENTS_TABLE / _DOCUMENTS_TABLE]); counts are call sites:

| class | meaning | action |
|-------|---------|--------|
| (a) marker writer | graph_sync `_mark_source_projected` (1); feed_publisher `_s28_claim_version` claim + release (2) | already `write_kind = marker` |
| (b) governed, already stamped | tracker_mutation create item + `_version_seq_update_parts` paths (generic PATCH/_handle_update_field transact Update, pwa close/reopen/worklog/note, _handle_log, create_record); document_api put + `_document_version_seq_update_parts` paths (patch, rejected-event, patch_section) | none |
| (c) governed, NOT stamped | see the fixed list in the commit message / report | FIXED: `write_kind = governed` added in the same call |
| (d) delete | project_service `_rollback_tracker_reference`, shared-layer/coordination `build_delete_transact_deletes` (REMOVE events are not filtered) | none |
| (e) non-record items | id/subtask/sequence counters (`counter#...`), `__feed__` version_seq counter, document version_seq counter, audit# items, idempotency markers (`_s28_*`), `_s28_commit` generic executor | allowlisted below; not projected as records |

This guard is static (ast only, hermetic): it finds every update_item / put_item / transact_write_items /
batch_write_item call under backend/lambda/*/*.py (+ the shared layer package) that targets the tracker or
documents table (or whose table cannot be resolved statically), and fails unless the call's
UpdateExpression / Item / TransactItems mentions `write_kind` (directly, or through a same-function data flow
into a known stamp helper) or the call is on the allowlist with a reason. Add a new unstamped writer and
this test fails. Run: python3 -m pytest tools/test_write_kind_stamp_guard_s47_0b.py -q
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

REPO = Path(__file__).resolve().parents[1]
LAMBDA_ROOT = REPO / "backend" / "lambda"

# DynamoDB write calls that can leave a stale marker behind. delete_item is exempt (REMOVE events pass).
WRITE_CALLS = {"update_item", "put_item", "transact_write_items", "batch_write_item"}

# Names that mean "the tracker table" / "the documents table" in this code base.
TRACKER_DOCS_NAMES = {
    "TRACKER_TABLE", "DYNAMODB_TABLE", "_CANONICAL_TRACKER_TABLE", "DOCUMENTS_TABLE", "_DOCUMENTS_TABLE",
    "DEFAULT_TRACKER_TABLE", "DEFAULT_DOCUMENTS_TABLE",
}
TRACKER_DOCS_LITERALS = {"devops-project-tracker", "documents"}

# Calls/names that stamp write_kind on behalf of the caller (their bodies are covered by their own tests).
STAMP_HELPERS = {
    "_version_seq_update_parts",            # tracker_mutation: ", ... write_kind = :wa_wkind" (also without the layer)
    "_document_version_seq_update_parts",   # document_api: "write_kind = :wa_wkind"
    "_stamp_version_seq_on_create_item",    # tracker_mutation: item["write_kind"] = governed
    "_stamp_governed_transact_updates",     # tracker_mutation: stamps shared-layer built Update entries
}

# (path relative to backend/lambda, enclosing function) -> reason. Keep one line per entry.
ALLOWLIST: Dict[Tuple[str, str], str] = {
    # (e) counters / generic executors on the tracker or documents table
    ("tracker_mutation/lambda_function.py", "_next_record_id"): "(e) counter item `counter#<type>`, not a projected record",
    ("tracker_mutation/lambda_function.py", "_next_subtask_suffix"): "(e) counter item `counter#subtask#...`, not a projected record",
    ("tracker_mutation/lambda_function.py", "_s28_commit"): "(e) generic TransactWriteItems executor; Update entries are stamped by their builders, Puts are audit#/idempotency/counter items",
    ("tracker_mutation/version_seq_util.py", "allocate_version_seq"): "(e) `__feed__` version_seq counter item",
    ("shared_layer/python/enceladus_shared/version_seq.py", "allocate_version_seq"): "(e) `__feed__` version_seq counter item",
    ("document_api/lambda_function.py", "_s28_commit"): "(e) generic TransactWriteItems executor; record Put/Update carry write_kind, rest are audit#/idempotency items",
    ("document_api/lambda_function.py", "_allocate_document_version_seq"): "(e) document version_seq counter item",
    ("coordination_api/lambda_function.py", "_next_tracker_sequence"): "(e) counter item `counter#<type>`, not a projected record",
    ("coordination_api/project_utils.py", "_next_tracker_sequence"): "(e) counter item `counter#<type>`, not a projected record",
    # (d) delete-only transaction
    ("coordination_api/lambda_function.py", "_handle_components_remove_edge"): "(d) TransactItems are Deletes only (build_delete_transact_deletes); REMOVE events are not filtered",
    # table cannot be resolved statically and is not the tracker/documents table
    ("changelog_api/backfill.py", "_put_item"): "operator backfill CLI; --table defaults to the deployment-manager table",
    ("convergence_telemetry/counter_store.py", "put_new"): "resource-API writer on CONVERGENCE_TABLE",
    ("convergence_telemetry/counter_store.py", "increment"): "resource-API writer on CONVERGENCE_TABLE",
    ("convergence_telemetry/counter_store.py", "mark_processed"): "resource-API writer on CONVERGENCE_TABLE",
    ("percolation_monitor/lambda_function.py", "_write_ddb"): "resource-API writer on PERCOLATION_TABLE",
    ("coordination_api/agent_id_alloc.py", "_next_seq"): "agent id/session tables (table_name param), not the tracker table",
    ("coordination_api/agent_id_alloc.py", "_put_node"): "agent id/session tables (table_name param), not the tracker table",
    ("coordination_api/agent_id_alloc.py", "_release_retired_session_checkouts"): "TransactItems over agent session / checkout token tables",
    ("coordination_api/agent_id_alloc.py", "_put_session_and_increment_usage"): "TransactItems over agent session / credential tables",
    ("coordination_api/agent_id_alloc.py", "retire_session_with_checkout_release"): "TransactItems over agent session / checkout token tables",
    ("coordination_api/budget_hierarchy.py", "emergency_wave_admission"): "drift telemetry table (DRIFT_TELEMETRY_TABLE)",
    ("coordination_api/intent_drift.py", "persist_intent_centroid_drift"): "drift telemetry table (DRIFT_TELEMETRY_TABLE)",
    ("graph_query_api/drift_telemetry.py", "emit_drift_record"): "drift telemetry table (table_name param)",
    ("graph_query_api/stigmergic_trace.py", "emit_stigmergic_trace"): "stigmergic trace table (table_name param)",
    ("deploy_parity_validator/lambda_function.py", "_patch_dpl_field"): "kwargs dict targets DEPLOY_TABLE (deployment records)",
    ("feed_publisher/lambda_function.py", "_mark_with_ids"): "kwargs dict targets FEED_PUBLISH_STATE_TABLE (feed state)",
    ("recompute_governance/lambda_function.py", "_cas_write"): "governance-version table (TABLE_NAME), not the tracker table",
}

SKIP_DIRS = {"tests", "__pycache__", "node_modules"}


def _is_test_file(path: Path) -> bool:
    return path.name.startswith("test_") or path.name == "conftest.py" or bool(SKIP_DIRS & set(path.parts))


def source_files() -> List[Path]:
    files = sorted(LAMBDA_ROOT.glob("*/*.py"))
    files += sorted(LAMBDA_ROOT.glob("*/*/*.py"))  # e.g. rhythm_cycle/tiers/*.py, graph_query_api/*
    files += sorted((LAMBDA_ROOT / "shared_layer" / "python" / "enceladus_shared").glob("*.py"))
    seen: Set[Path] = set()
    out = []
    for f in files:
        if f in seen or _is_test_file(f.relative_to(LAMBDA_ROOT)):
            continue
        seen.add(f)
        out.append(f)
    return out


# ---------------------------------------------------------------------------------------------
# analysis
# ---------------------------------------------------------------------------------------------

def _base_name(node: ast.AST) -> str:
    while isinstance(node, (ast.Subscript, ast.Attribute)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _names(node: ast.AST) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _is_evidence(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and "write_kind" in node.value:
        return True
    if isinstance(node, ast.keyword) and node.arg == "write_kind":  # dict(item, write_kind="governed")
        return True
    if isinstance(node, ast.Name) and node.id in STAMP_HELPERS:
        return True
    return isinstance(node, ast.Attribute) and node.attr in STAMP_HELPERS


def _has_evidence(node: ast.AST) -> bool:
    return any(_is_evidence(n) for n in ast.walk(node))


def _affecting_statements(func: ast.AST) -> Dict[str, List[ast.AST]]:
    """name -> statements/expressions in `func` that assign to it or mutate it (x = .., x += .., x[k] = ..,
    x.append/extend/update(..), helper(x))."""
    out: Dict[str, List[ast.AST]] = {}

    def add(name: str, node: ast.AST) -> None:
        if name:
            out.setdefault(name, []).append(node)

    for n in ast.walk(func):
        if n is not func and isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            add(n.name, n)  # nested item builders, e.g. `_rel_item`
        elif isinstance(n, ast.Assign):
            for t in n.targets:
                for tt in (t.elts if isinstance(t, (ast.Tuple, ast.List)) else [t]):
                    add(_base_name(tt), n)
        elif isinstance(n, (ast.AugAssign, ast.AnnAssign)):
            add(_base_name(n.target), n)
        elif isinstance(n, ast.Call):
            if isinstance(n.func, ast.Attribute):
                add(_base_name(n.func.value), n)
            for a in n.args:
                add(_base_name(a), n)
    return out


def _arg_exprs(call: ast.Call) -> List[ast.AST]:
    wanted = {"UpdateExpression", "Item", "TransactItems", "RequestItems"}
    exprs: List[ast.AST] = [k.value for k in call.keywords if k.arg in wanted]
    exprs += [k.value for k in call.keywords if k.arg is None]  # **kwargs
    return exprs


def _stamped(call: ast.Call, func: ast.AST | None) -> bool:
    exprs = _arg_exprs(call)
    if any(_has_evidence(e) for e in exprs):
        return True
    if func is None:
        return False
    affect = _affecting_statements(func)
    frontier: Set[str] = set()
    for e in exprs:
        frontier |= _names(e)
    seen: Set[str] = set()
    while frontier:
        name = frontier.pop()
        if name in seen:
            continue
        seen.add(name)
        for stmt in affect.get(name, []):
            if stmt is call:
                continue
            if _has_evidence(stmt):
                return True
            frontier |= _names(stmt) - seen
    return False


def _table_class(call: ast.Call, func: ast.AST | None) -> str:
    """'tracker' (tracker/documents named), 'other' (a different named TABLE constant) or 'unresolved'."""
    if call.func.attr in ("transact_write_items", "batch_write_item"):  # type: ignore[union-attr]
        scope = func if func is not None else call
        for n in ast.walk(scope):
            if isinstance(n, ast.Name) and n.id in TRACKER_DOCS_NAMES:
                return "tracker"
            if isinstance(n, ast.Constant) and n.value in TRACKER_DOCS_LITERALS:
                return "tracker"
        return "unresolved"
    for k in call.keywords:
        if k.arg == "TableName":
            v = k.value
            if any(isinstance(n, ast.Name) and n.id in TRACKER_DOCS_NAMES for n in ast.walk(v)):
                return "tracker"
            if isinstance(v, ast.Constant) and v.value in TRACKER_DOCS_LITERALS:
                return "tracker"
            if isinstance(v, ast.Name) and v.id.isupper() and v.id.endswith("TABLE"):
                return "other"
            return "unresolved"
    return "unresolved"  # **kwargs or resource-API Table(...).put_item(Item=...)


def _enclosing_function(tree: ast.AST) -> Dict[ast.AST, ast.AST | None]:
    parent: Dict[ast.AST, ast.AST] = {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parent[c] = p
    out: Dict[ast.AST, ast.AST | None] = {}
    for n in ast.walk(tree):
        cur, found = n, None
        while cur in parent:
            cur = parent[cur]
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found = cur
                break
        out[n] = found
    return out


def analyze_source(source: str, rel_path: str) -> List[dict]:
    """Return one record per tracker/documents-or-unresolved write call: {path, line, func, call, table, stamped, allowed}."""
    tree = ast.parse(source)
    encl = _enclosing_function(tree)
    rows = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in WRITE_CALLS):
            continue
        func = encl.get(n)
        table = _table_class(n, func)
        if table == "other":
            continue
        fname = func.name if func is not None else "<module>"
        rows.append({
            "path": rel_path, "line": n.lineno, "func": fname, "call": n.func.attr, "table": table,
            "stamped": _stamped(n, func), "allowed": (rel_path, fname) in ALLOWLIST,
        })
    return rows


def analyze_repo() -> List[dict]:
    rows: List[dict] = []
    for f in source_files():
        rel = f.relative_to(LAMBDA_ROOT).as_posix()
        rows.extend(analyze_source(f.read_text(encoding="utf-8"), rel))
    return rows


def violations(rows: Iterable[dict]) -> List[dict]:
    return [r for r in rows if not r["stamped"] and not r["allowed"]]


# ---------------------------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------------------------

class WriteKindStampGuard(unittest.TestCase):
    def test_every_tracker_or_documents_writer_stamps_write_kind(self):
        bad = violations(analyze_repo())
        self.assertEqual(
            bad, [],
            "write_kind stamp missing on tracker/documents write(s). A sticky write_kind=marker would make the event "
            "source mappings drop this writer's MODIFY events (graph/feed/AppSync/audit never see the change). "
            "Add `write_kind = :wk` ({'S': 'governed'}) to the same UpdateExpression/Item, or allowlist the call with a "
            "reason if the item is not a projected record:\n" + "\n".join(
                f"  {r['path']}:{r['line']} {r['func']}() {r['call']} [{r['table']}]" for r in bad),
        )

    def test_scanner_sees_the_known_writers(self):
        rows = analyze_repo()
        by_path = {r["path"] for r in rows if r["table"] == "tracker"}
        for expected in ("tracker_mutation/lambda_function.py", "document_api/lambda_function.py",
                         "coordination_api/lambda_function.py"):
            self.assertIn(expected, by_path, f"scanner no longer finds tracker/documents writers in {expected}")
        # marker writers resolve their table from the stream image (variable), so they show up as 'unresolved'
        marker_paths = {r["path"] for r in rows if r["stamped"] and r["table"] == "unresolved"}
        for expected in ("graph_sync/lambda_function.py", "feed_publisher/lambda_function.py"):
            self.assertIn(expected, marker_paths)
        self.assertGreater(len([r for r in rows if r["table"] == "tracker" and r["stamped"]]), 30)

    def test_allowlist_has_no_stale_entries(self):
        live = {(r["path"], r["func"]) for r in analyze_repo() if not r["stamped"]}
        stale = sorted(k for k in ALLOWLIST if k not in live)
        self.assertEqual(stale, [], f"allowlist entries that no longer match an unstamped write: {stale}")

    def test_marker_writers_are_not_governed(self):
        # (a) the three projection writers must keep setting marker, never governed.
        for rel, needle in (("graph_sync/lambda_function.py", '":wk": {"S": "marker"}'),
                            ("feed_publisher/lambda_function.py", '":wk": {"S": "marker"}')):
            text = (LAMBDA_ROOT / rel).read_text(encoding="utf-8")
            self.assertIn(needle, text, rel)
            self.assertNotIn('"S": "governed"', text, f"{rel} is a projection writer and must never stamp governed")

    # ---- the guard itself must catch a new unstamped writer ----------------------------------

    def test_detects_unstamped_update_item(self):
        src = (
            "def f(ddb):\n"
            "    ddb.update_item(TableName=TRACKER_TABLE, Key={}, UpdateExpression='SET a = :a',\n"
            "                    ExpressionAttributeValues={':a': {'S': 'x'}})\n"
        )
        bad = violations(analyze_source(src, "newlambda/lambda_function.py"))
        self.assertEqual([(r["func"], r["call"]) for r in bad], [("f", "update_item")])

    def test_detects_unstamped_put_and_transact(self):
        src = (
            "def p(ddb):\n"
            "    ddb.put_item(TableName=DOCUMENTS_TABLE, Item={'document_id': {'S': 'd'}})\n"
            "def t(ddb):\n"
            "    ddb.transact_write_items(TransactItems=[{'Put': {'TableName': DYNAMODB_TABLE, 'Item': {}}}])\n"
        )
        bad = violations(analyze_source(src, "newlambda/lambda_function.py"))
        self.assertEqual(sorted(r["func"] for r in bad), ["p", "t"])

    def test_detects_unresolved_table(self):
        src = "def u(ddb, table):\n    ddb.update_item(TableName=table, Key={}, UpdateExpression='SET a = :a')\n"
        self.assertEqual(len(violations(analyze_source(src, "newlambda/lambda_function.py"))), 1)

    def test_accepts_stamped_variants(self):
        src = (
            "def a(ddb):\n"
            "    ddb.update_item(TableName=TRACKER_TABLE, Key={}, UpdateExpression='SET write_kind = :wk, a = :a')\n"
            "def b(ddb):\n"
            "    parts = ['a = :a']\n"
            "    parts.append('write_kind = :wk')\n"
            "    expr = 'SET ' + ', '.join(parts)\n"
            "    ddb.update_item(TableName=DYNAMODB_TABLE, Key={}, UpdateExpression=expr)\n"
            "def c(ddb):\n"
            "    expr = 'SET a = :a'\n"
            "    vexpr, vvals = _version_seq_update_parts()\n"
            "    expr += vexpr\n"
            "    ddb.update_item(TableName=DYNAMODB_TABLE, Key={}, UpdateExpression=expr)\n"
            "def d(ddb):\n"
            "    item = {'a': 1}\n"
            "    item['write_kind'] = {'S': 'governed'}\n"
            "    ddb.put_item(TableName=DOCUMENTS_TABLE, Item=item)\n"
            "def e(ddb):\n"
            "    ddb.update_item(TableName=DEPLOY_TABLE, Key={}, UpdateExpression='SET a = :a')\n"  # other table: ignored
            "def f(ddb):\n"
            "    ddb.delete_item(TableName=TRACKER_TABLE, Key={})\n"  # delete: exempt
        )
        self.assertEqual(violations(analyze_source(src, "newlambda/lambda_function.py")), [])


if __name__ == "__main__":
    unittest.main()
