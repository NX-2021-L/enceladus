#!/usr/bin/env python3
"""DVP-TSK-840: generate the ui-v2 parity inputs for `io-kit parity`.

Writes, next to this script:
  routes.yaml  route manifest (schema 1.0.0): one entry per TanStack route in
               src/routes/router.tsx, with the api/v1 handlers its code reaches.
  map.yaml     action -> handler verdict mapping for the enceladus surface
               (the hand table of DOC-408DB108D7B9 s2, now code: ACTION_RULES).

Method (stdlib only, deterministic, no network):
  1. routes   : parse router.tsx (createRoute / createRecordRoute /
                createDocumentRecordRoute / session + agent factories / the
                shellNavRoutes placeholder array).
  2. reach    : from each route's component file follow relative imports
                (tests excluded). Files under src/api/ are NOT walked; they are
                split into top-level symbols, and a symbol is "reached" when its
                name is used by a reached non-api file (or by a reached api
                symbol). This keeps a route from inheriting every endpoint of a
                shared module such as client.ts.
  3. handlers : every reached api symbol is scanned (comments stripped) for
                `${API_BASE}/...`, `${FEED_BASE}/...` and '/api/v1/...' strings.
                Path params are normalised ({project}, {id}, {type}), queries are
                dropped except the keys in KEPT_QUERY, the HTTP method is read
                from quoted methods in the symbol (default GET).
  4. map      : ACTION_RULES resolves each rule to a handler string that the
                scan actually produced. A rule that matches no handler aborts
                the run, so the map cannot drift from the code silently.

`--check` regenerates in memory and exits 1 if the committed files differ.
Both generated files are committed; CI regenerates and checks them.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SRC = HERE.parent / "src"
ROUTER = SRC / "routes" / "router.tsx"
CAPS = REPO / "tools" / "enceladus-mcp-server" / "parity" / "caps.json"

STACK = "enceladus.jreese.net"
SCHEMA_VERSION = "1.0.0"
GENERATED_AT = "2026-10-10T00:00:00Z"  # fixed on purpose: output must be reproducible
ROUTE_SURFACE = "enceladus"  # caps.json "surface"; the old fixtures called it enceladus_v2
KEPT_QUERY = ("mode", "search_type")

# Auth is not derivable from the route tree. Everything is session-cookie
# authed (AuthGate); /escalations additionally has the 3 server-side gates.
ROUTE_AUTH = {"/escalations": "session + server-side human-principal + S3 allowlist (3 gates)"}
DEFAULT_AUTH = "session"

# Component per route when the route is declared by a factory rather than a
# lazyRouteComponent/component property.
FACTORY_COMPONENT = {
    "createRecordRoute": "routes/recordRoute.tsx (createRecordRoute)",
    "createDocumentRecordRoute": "routes/recordRoute.tsx (createDocumentRecordRoute)",
}

# Route-order: the manifest is sorted like the router's addChildren list.
STMT = re.compile(r"^(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function|const|let|class|type|interface|enum)\s+(\w+)", re.M)
IMPORT = re.compile(r"""(?:from\s+|import\s*\(\s*|import\s+)['"](\.[^'"]+)['"]""")
TOKEN = re.compile(r"[A-Za-z_$][\w$]*")
METHOD = re.compile(r"""'(GET|POST|PATCH|PUT|DELETE)'(?!\s*\|)""")
URLSTR = re.compile(r"""([`'"])((?:\$\{(?:API_BASE|FEED_BASE)\}|/api/v1)[^`'"]*)\1|(`)(\$\{(?:API_BASE|FEED_BASE)\}[^`]*)`""")

PARAM_NAMES = {
    "projectId": "project", "project": "project", "documentId": "id", "recordId": "id",
    "sessionId": "id", "escalationId": "id", "recordType": "type", "agentTypeId": "id",
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)(?<![:'\"`])//.*$", "", text)


def read(path: Path) -> str:
    return strip_comments(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- source graph
def is_test(p: Path) -> bool:
    return ".test." in p.name or "test" in p.relative_to(SRC).parts[:1]


def resolve(frm: Path, spec: str) -> Path | None:
    base = (frm.parent / spec).resolve()
    for cand in (base, base.with_suffix(".ts"), base.with_suffix(".tsx"), base / "index.ts", base / "index.tsx"):
        if cand.is_file() and cand.suffix in (".ts", ".tsx"):
            return cand
    return None


def in_api(p: Path) -> bool:
    return p.relative_to(SRC).parts[0] == "api"


def split_symbols(path: Path) -> dict[str, str]:
    text = read(path)
    marks = [(m.start(), m.group(1)) for m in STMT.finditer(text)]
    out: dict[str, str] = {}
    for i, (start, name) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        out[name] = out.get(name, "") + text[start:end]
    return out


_symbols: dict[Path, dict[str, str]] = {}


def api_symbols() -> dict[str, tuple[Path, str]]:
    if not _symbols:
        for p in sorted((SRC / "api").glob("*.ts")):
            if not is_test(p):
                _symbols[p] = split_symbols(p)
    table: dict[str, tuple[Path, str]] = {}
    for p, syms in _symbols.items():
        for name, body in syms.items():
            table.setdefault(name, (p, body))
    return table


def reach_files(entry: Path) -> set[Path]:
    seen: set[Path] = set()
    todo = [entry]
    while todo:
        f = todo.pop()
        if f in seen or is_test(f):
            continue
        seen.add(f)
        if in_api(f):
            continue  # api modules are handled symbol by symbol
        for spec in IMPORT.findall(read(f)):
            r = resolve(f, spec)
            if r is not None:
                todo.append(r)
    return seen


def reached_api_symbols(files: set[Path], extra_tokens: set[str]) -> set[str]:
    """Api symbols a route reaches, following symbol -> symbol references and the
    non-api modules an api module imports (e.g. sync/readThrough.ts, which owns
    the record GET behind queryOptions)."""
    table = api_symbols()
    seen_files = set(files)
    used = set(extra_tokens)
    for f in files:
        if not in_api(f):
            used |= set(TOKEN.findall(read(f)))
    hit: set[str] = set()
    todo = [t for t in used if t in table]
    while todo:
        name = todo.pop()
        if name in hit:
            continue
        hit.add(name)
        path, body = table[name]
        new_tokens = set(TOKEN.findall(body))
        for spec in IMPORT.findall(read(path)):
            r = resolve(path, spec)
            if r is not None and not in_api(r) and r not in seen_files:
                extra = reach_files(r)
                seen_files |= extra
                for f in extra:
                    if not in_api(f):
                        new_tokens |= set(TOKEN.findall(read(f)))
        todo += [t for t in new_tokens if t in table and t not in hit]
    return hit


# ------------------------------------------------------------------ endpoints
def local_base(path: Path) -> str:
    """The module's own API_BASE literal when it has one (documents.ts), else /api/v1."""
    m = re.search(r"const API_BASE\s*=\s*'([^']+)'", read(path))
    return m.group(1) if m else "/api/v1"


def normalise(raw: str, base: str) -> str:
    s = raw
    if s.startswith("${FEED_BASE}"):
        s = "/api/v1/feed" + s[len("${FEED_BASE}"):]
    elif s.startswith("${API_BASE}"):
        s = base + s[len("${API_BASE}"):]
    s = re.sub(r"\$\{encodeURIComponent\((\w+)\)\}", lambda m: "{%s}" % PARAM_NAMES.get(m.group(1), m.group(1)), s)
    s = re.sub(r"\$\{(\w+)\}", lambda m: "{%s}" % PARAM_NAMES.get(m.group(1), m.group(1)), s)
    s = re.sub(r"\$\{.*$", "", s)  # a nested expression is always a query suffix
    path, _, query = s.partition("?")
    keep = [kv for kv in query.split("&") if kv.split("=")[0] in KEPT_QUERY and "$" not in kv]
    return path.rstrip("/") + ("?" + "&".join(keep) if keep else "")


def endpoints_of(body: str, base: str) -> list[str]:
    meths = sorted(set(METHOD.findall(body))) or ["GET"]
    # `decision: 'approve' | 'deny'` style unions expand a {decision} path segment
    unions = {m.group(1): re.findall(r"'([\w-]+)'", m.group(2))
              for m in re.finditer(r"(\w+):\s*('[\w-]+'(?:\s*\|\s*'[\w-]+')+)", body)}
    found: set[str] = set()
    for m in re.finditer(r"""[`'"]((?:\$\{(?:API_BASE|FEED_BASE)\}|/api/v1)(?:[^`'"\\]|\\.)*)[`'"]""", body):
        norm = normalise(m.group(1), base)
        if norm in ("/api/v1", "/api/v1/feed"):
            continue  # a bare base constant, not a call
        slots = [k for k in unions if "{%s}" % k in norm]
        variants = [norm]
        for k in slots:
            variants = [v.replace("{%s}" % k, val) for v in variants for val in unions[k]]
        found.update(variants)
    return [f"{mm} {e}" for e in sorted(found) for mm in meths]


# ---------------------------------------------------------------------- routes
def parse_routes() -> list[dict]:
    text = ROUTER.read_text(encoding="utf-8")
    code = strip_comments(text)
    # block split: every top-level `const X = ...` up to the next top-level const
    marks = [(m.start(), m.group(1)) for m in re.finditer(r"^const (\w+) =", code, re.M)]
    blocks = {name: code[s:(marks[i + 1][0] if i + 1 < len(marks) else len(code))] for i, (s, name) in enumerate(marks)}

    tree = re.search(r"addChildren\(\[(.*?)\]\)", code, re.S).group(1)
    order = [t.strip() for t in tree.split(",") if t.strip()]

    # shellNavRoutes placeholders
    nav = re.search(r"const shellNavRoutes = \[(.*?)\] as const", code, re.S).group(1)
    placeholders = re.findall(r"path:\s*'([^']+)'", nav)

    def const_path(sym: str) -> str:
        m = re.search(rf"export const {sym}\s*=\s*'([^']+)'", read(SRC / "routes" / "recordLink.ts"))
        return m.group(1)

    routes: list[dict] = []
    for name in order:
        if name == "...placeholderRoutes":
            for p in placeholders:
                routes.append({"path": p, "component": "routes/PlaceholderRoute.tsx", "entry": SRC / "routes" / "PlaceholderRoute.tsx", "tokens": set()})
            continue
        blk = blocks[name]
        pm = re.search(r"path:\s*'([^']+)'", blk)
        path = pm.group(1) if pm else None
        tokens = set(TOKEN.findall(blk))
        if re.search(r"= createSessionDetailRoute", blk):
            path = const_path("SESSION_ROUTE_PATH")
            entry = SRC / "routes" / "SessionDetailRoute.tsx"
            comp = "routes/SessionDetailRoute.tsx"
        elif re.search(r"= createAgentDetailRoute", blk):
            path = const_path("AGENT_ROUTE_PATH")
            entry = SRC / "routes" / "AgentDetailRoute.tsx"
            comp = "routes/AgentDetailRoute.tsx"
        elif re.search(r"= createRecordRoute|= createDocumentRecordRoute", blk):
            factory = re.search(r"= (create\w*RecordRoute)", blk).group(1)
            entry = SRC / "routes" / "recordRoute.tsx"
            comp = FACTORY_COMPONENT[factory]
        else:
            lm = re.search(r"import\('(\./\w+)'\)", blk)
            cm = re.search(r"component:\s*(\w+)\s*[,}\n]", blk)
            if lm:
                entry = resolve(ROUTER, lm.group(1))
            else:
                imp = re.search(rf"import \{{[^}}]*\b{cm.group(1)}\b[^}}]*\}} from '(\./[^']+)'", code)
                entry = resolve(ROUTER, imp.group(1))
            comp = str(entry.relative_to(SRC))
        if path is None:
            raise SystemExit(f"parity: no path for route const {name}")
        routes.append({"path": path, "component": comp, "entry": entry, "tokens": tokens})
    return routes


def build_routes() -> list[dict]:
    table = api_symbols()
    out = []
    for r in parse_routes():
        files = reach_files(r["entry"])
        syms = reached_api_symbols(files, r["tokens"])
        handlers: list[str] = []
        for s in sorted(syms):
            for h in endpoints_of(table[s][1], local_base(table[s][0])):
                if h not in handlers:
                    handlers.append(h)
        out.append({
            "path": r["path"],
            "component": "frontend/ui-v2/src/" + r["component"],
            "handlers": sorted(handlers),
            "auth": ROUTE_AUTH.get(r["path"], DEFAULT_AUTH),
            "surface": ROUTE_SURFACE,
        })
    return out


# ------------------------------------------------------------------------- map
# action -> (verdict, handler regex or None, note). Judged once (DOC-408DB108D7B9
# s2) and kept here so a change of the route code that breaks a judgement
# aborts generation instead of silently turning into a stale-handler finding.
# `covered` maps to exactly one handler, `partial` to the nearest one; any
# action not listed is written as `missing` with the generic note.
MISSING_NOTE = "no route handler names the action or an equivalent HTTP handler"
PLACEHOLDER_NOTE = "placeholder route /deployments (handlers [])"
G = r"GET /api/v1/"
ACTION_RULES: dict[str, tuple[str, str | None, str | None]] = {
    "projects.list": ("covered", G + r"projects$", None),
    "tracker.get": ("covered", G + r"tracker/\{project\}/\{type\}/\{id\}$", None),
    "tracker.list": ("partial", G + r"tracker/\{project\}\?mode=census$", "route serves census mode only, no filtered list"),
    "documents.search": ("covered", G + r"documents/search$", None),
    "documents.get": ("covered", G + r"documents/\{id\}$", None),
    "documents.list": ("covered", G + r"documents$", None),
    "documents.manifest": ("covered", G + r"documents/\{id\}/manifest$", None),
    "documents.history": ("covered", G + r"changelog/history$", None),
    "documents.diff": ("covered", G + r"documents/\{id\}/diff$", None),
    "reference.search": ("partial", G + r"documents/search$", "/docs calls generic document search; backend equivalence to reference.search not shown"),
    "changelog.history": ("covered", G + r"changelog/history$", None),
    "governance.get": ("partial", G + r"documents/search$", "/governance route lists governance docs by search; no file_name fetch handler"),
    "tracker.graphsearch": ("covered", G + r"tracker/graphsearch$", None),
    "escalation.get": ("partial", G + r"coordination/escalations$", "list-with-filter only; no per-escalation GET handler"),
    "escalation.list": ("covered", G + r"coordination/escalations$", None),
    "agent.list": ("covered", G + r"coordination/agents/sessions$", None),
    "agent.type.list": ("covered", G + r"coordination/agents/types$", None),
    "tracker.set": ("partial", r"PATCH /api/v1/tracker/\{project\}/\{type\}/\{id\}$", "generic record PATCH; field coverage and governance_hash handling not shown in manifest"),
    "checkout.task": ("covered", r"POST /api/v1/tracker/\{project\}/\{type\}/\{id\}/checkout$", None),
    "checkout.advance": ("partial", r"PATCH /api/v1/tracker/\{project\}/\{type\}/\{id\}$", "status advance goes through the generic record PATCH"),
}
DEPLOY_ACTIONS = ("deploy.state_get", "deploy.history", "deploy.history_list", "deploy.status", "deploy.status_get", "deploy.pending_requests")


def build_map(routes: list[dict]) -> dict[str, dict]:
    handlers = sorted({h for r in routes for h in r["handlers"]})
    caps = json.loads(CAPS.read_text(encoding="utf-8"))
    names = [a["name"] for a in caps["actions"]]
    unknown = sorted(set(ACTION_RULES) - set(names))
    if unknown:
        raise SystemExit(f"parity: ACTION_RULES names actions not in caps.json: {unknown}")
    entries: dict[str, dict] = {}
    for name in names:
        rule = ACTION_RULES.get(name)
        if rule is None:
            note = PLACEHOLDER_NOTE if name in DEPLOY_ACTIONS else MISSING_NOTE
            entries[name] = {"verdict": "missing", "note": note}
            continue
        verdict, rx, note = rule
        matches = [h for h in handlers if re.match(rx, h)]
        if len(matches) != 1:
            raise SystemExit(f"parity: rule for {name} ({rx}) matched {len(matches)} handlers: {matches}\n  available: {handlers}")
        e: dict[str, str] = {}
        if verdict != "covered":
            e["verdict"] = verdict
        e["handler"] = matches[0]
        if note:
            e["note"] = note
        entries[name] = e
    return entries


# ---------------------------------------------------------------------- output
def q(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def render_routes(routes: list[dict]) -> str:
    L = [
        "# generated by frontend/ui-v2/parity/generate_parity.py from src/routes/router.tsx and src/api/*.ts (DVP-TSK-840); do not edit",
        f"schemaVersion: {q(SCHEMA_VERSION)}",
        f"stack: {q(STACK)}",
        f"generatedAt: {q(GENERATED_AT)}",
        "routes:",
    ]
    for r in routes:
        L.append(f"  - path: {q(r['path'])}")
        L.append(f"    component: {q(r['component'])}")
        if r["handlers"]:
            L.append("    handlers:")
            L += [f"      - {q(h)}" for h in r["handlers"]]
        else:
            L.append("    handlers: []")
        L.append(f"    auth: {q(r['auth'])}")
        L.append(f"    surface: {q(r['surface'])}")
    return "\n".join(L) + "\n"


def render_map(entries: dict[str, dict]) -> str:
    L = [
        "# generated by frontend/ui-v2/parity/generate_parity.py (ACTION_RULES); do not edit",
        f"stack: {q(STACK)}",
        "surfaces:",
        f"  {ROUTE_SURFACE}:",
    ]
    for name, e in entries.items():
        L.append(f"    {q(name)}:")
        for k in ("verdict", "handler", "note"):
            if k in e:
                L.append(f"      {k}: {q(e[k])}")
    return "\n".join(L) + "\n"


def main(argv: list[str]) -> int:
    routes = build_routes()
    entries = build_map(routes)
    outs = {HERE / "routes.yaml": render_routes(routes), HERE / "map.yaml": render_map(entries)}
    if "--check" in argv:
        stale = [p.name for p, body in outs.items() if not p.is_file() or p.read_text(encoding="utf-8") != body]
        if stale:
            print(f"parity: committed file(s) out of date: {', '.join(stale)}; run python3 {Path(__file__).name}", file=sys.stderr)
            return 1
        print("parity: routes.yaml and map.yaml are current")
        return 0
    for p, body in outs.items():
        p.write_text(body, encoding="utf-8")
        print(f"wrote {p.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
