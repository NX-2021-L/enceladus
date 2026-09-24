#!/usr/bin/env python3
"""ENC-TSK-H94 — Near-duplicate retrieval MEASUREMENT HARNESS (ENC-TSK-H34 AC-3).

Quantifies whether the ENC-TSK-H92 correlation-aware encoding improves
near-duplicate retrieval. It captures a BEFORE run (encoding OFF) and an AFTER
run (encoding ON) over a held-out near-duplicate eval set, computes recall@k and
precision@1 for each, and renders an explicit met / not-met verdict against a
>=5% precision@1 acceptance bar.

Two-phase usage (the LIVE phase runs later in a product-lead terminal):

  capture   Run the eval set through a retrieval surface and write a
            ``run_<label>.json`` with precision@1 / recall@k / per-query rows.
            Run twice against gamma — once with the encoding flag OFF (label
            ``before``) and once ON (label ``after``).
  compare   Load the two captured runs, compute the precision@1 delta, and write
            a ``verdict.json`` + a human-readable summary.

Retrieval surface (capture, LIVE — defensive, NOT unit-tested live)
-------------------------------------------------------------------
``--source gamma`` queries the hybrid retrieval path via boto3
``lambda.invoke`` against ``devops-graph-query-api-gamma`` with a synthetic API
Gateway v2 GET event for ``/api/v1/tracker/graphsearch`` and
``queryStringParameters={search_type:"hybrid", project_id, query, top_n}``. The
``x-coordination-internal-key`` header is sourced from the invoked function's OWN
env via ``get_function_configuration`` (the ENC-LSN-039 pattern, mirroring
``correlation_analysis_h91.py``). The hybrid response carries
``nodes:[{record_id, ...}]`` ordered by fused score; the harness reduces each to
its ranked ``record_id`` list. The encoding ON/OFF state is owned by the gamma
function's flag env (the ENC-TSK-H92 apply step) and is NOT toggled from here —
the operator captures ``before`` then flips the flag and captures ``after``.

The retrieval call is INJECTABLE: every metric/capture function takes a
``retrieve_fn(query, k) -> list[record_id]`` so the unit tests drive it with a
pure in-memory stub. NO live AWS/MCP call happens in the tests.

Metrics (the testable core)
---------------------------
* ``precision_at_1(results, eval_set)`` — fraction of eval items whose rank-1
  retrieved record_id equals the expected record_id.
* ``recall_at_k(results, eval_set, k)`` — fraction whose expected record_id is
  within the top-k retrieved.
* ``capture_run(eval_set, retrieve_fn, k, label)`` — assemble a full run dict.
* ``compare(before_run, after_run, bar)`` — the verdict.

No-fabrication guarantee (AC-3)
-------------------------------
``compare`` NEVER invents an after/delta. When ``after_run`` is absent it returns
``verdict="baseline_only"`` with ``precision_at_1_after`` and ``delta`` set to
``None``. Every number in a run comes from an actually-captured retrieval; this
module never synthesizes a metric.

``--generated-at`` is the ONLY timestamp source; ``datetime.now()`` is NEVER
called (at import or runtime). The field is left ``None`` when not supplied.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Optional numpy. Imported once at module load. The metrics here are pure stdlib
# arithmetic; numpy is NOT required and the unit tests run without it. It is
# referenced only so a caller may inject numpy-typed scores without surprise.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - numpy presence is environment-specific
    import numpy as np  # type: ignore  # noqa: F401
except Exception:  # pragma: no cover - numpy absent is a supported config
    np = None  # type: ignore

# Contract constants.
RUN_VERSION = "h94.v1"
VERDICT_VERSION = "h94.verdict.v1"

DEFAULT_K = 10
DEFAULT_BAR = 0.05
DEFAULT_PROJECT_ID = "enceladus"
DEFAULT_OUT_DIR = "./h94_results"
DEFAULT_GAMMA_FUNCTION = "devops-graph-query-api-gamma"
DEFAULT_HOLDOUT_FRAC = 1.0  # by default the whole derived set is held out

# Canonical standing-projection name (ENC-FTR-101 Option B); the gamma health
# block reports this under graph_projection.name.
CANONICAL_PROJECTION_NAME = "gds_standing_enceladus"

# Verdict literals.
VERDICT_MET = "met"
VERDICT_NOT_MET = "not_met"
VERDICT_BASELINE_ONLY = "baseline_only"

# Eval-item keys.
EVAL_QUERY = "query"
EVAL_EXPECTED = "expected"
EVAL_CLUSTER = "cluster"

_GRAPHSEARCH_PATH = "/api/v1/tracker/graphsearch"


# ===========================================================================
# Eval-set construction
# ===========================================================================
def build_eval_set(
    pairs: Sequence[Dict[str, Any]],
    corpus: Sequence[Dict[str, Any]],
    holdout_frac: float = DEFAULT_HOLDOUT_FRAC,
) -> List[Dict[str, Any]]:
    """Derive a held-out near-duplicate eval set from the ENC-TSK-H91
    ``pairs.jsonl`` + corpus.

    Each DISTINCT record appearing in any high-correlation pair becomes a
    self-retrieval eval item: the item's own title/text is the query and its own
    record_id is the ``expected`` answer. Crosstalk makes the near-duplicate
    outrank the true item under the un-encoded path — exactly the failure the
    ENC-TSK-H92 encoding is meant to fix — so self-retrieval precision@1 is a
    faithful probe of the improvement.

    The ``cluster`` id groups records that are linked (directly or transitively)
    through pairs, so a held-out fraction can reserve whole clusters. Only
    endpoints that resolve to a corpus record with usable query text are kept.

    ``holdout_frac`` in (0, 1] reserves the first ``ceil(frac * n)`` items (by
    stable cluster order) as the held-out set returned here. ``1.0`` keeps all.
    """
    if not 0.0 < holdout_frac <= 1.0:
        raise ValueError(f"holdout_frac must be in (0, 1]; got {holdout_frac!r}")

    by_id = _corpus_by_id(corpus)

    # Union-find over pair endpoints to assign a stable cluster id per record.
    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        # Path-compress.
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            # Keep the lexicographically smaller root for determinism.
            lo, hi = (ra, rb) if ra <= rb else (rb, ra)
            parent[hi] = lo

    ordered_ids: List[str] = []
    seen: Dict[str, None] = {}
    for p in pairs:
        a, b = p.get("a"), p.get("b")
        for rid in (a, b):
            if rid is not None and rid not in seen:
                seen[rid] = None
                ordered_ids.append(rid)
        if a is not None and b is not None:
            union(a, b)

    items: List[Dict[str, Any]] = []
    for rid in ordered_ids:
        text = _record_query_text(by_id.get(rid))
        if not text:
            continue
        items.append({
            EVAL_QUERY: text,
            EVAL_EXPECTED: rid,
            EVAL_CLUSTER: find(rid),
        })

    if not items:
        return []

    # Held-out reservation: take the first ceil(frac * n) items in cluster-stable
    # order so reserved clusters stay intact (items are already first-seen order,
    # which keeps cluster members adjacent enough for a deterministic split).
    n = len(items)
    keep = n if holdout_frac >= 1.0 else max(1, _ceil_int(holdout_frac * n))
    return items[:keep]


def load_eval_set_from_file(path: str) -> List[Dict[str, Any]]:
    """Load an eval-set JSON: either ``{"eval_set":[...]}`` / ``{"items":[...]}``
    or a bare list of ``{"query","expected","cluster"}`` dicts. Items missing a
    query or expected are dropped defensively.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        raw = data.get("eval_set")
        if raw is None:
            raw = data.get("items", [])
    elif isinstance(data, list):
        raw = data
    else:
        raw = []
    items: List[Dict[str, Any]] = []
    for it in raw:
        if not isinstance(it, dict):
            continue
        if it.get(EVAL_QUERY) is None or it.get(EVAL_EXPECTED) is None:
            continue
        items.append({
            EVAL_QUERY: it[EVAL_QUERY],
            EVAL_EXPECTED: it[EVAL_EXPECTED],
            EVAL_CLUSTER: it.get(EVAL_CLUSTER),
        })
    return items


def _corpus_by_id(corpus: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    by_id: Dict[str, Dict[str, Any]] = {}
    for n in corpus:
        if isinstance(n, dict) and n.get("record_id") is not None:
            by_id[n["record_id"]] = n  # last write wins on duplicate ids
    return by_id


def _record_query_text(node: Optional[Dict[str, Any]]) -> str:
    """Best-effort query text for a corpus record: prefer title, then text/body.
    Returns "" when none is usable (such records are skipped as eval items).
    """
    if not isinstance(node, dict):
        return ""
    for key in ("title", "text", "body", "name", "summary"):
        val = node.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _ceil_int(x: float) -> int:
    i = int(x)
    return i if float(i) == x else i + 1


# ===========================================================================
# Metrics (the testable core)
# ===========================================================================
def precision_at_1(
    results: Dict[str, Sequence[str]],
    eval_set: Sequence[Dict[str, Any]],
) -> float:
    """Fraction of eval items whose RANK-1 retrieved record_id equals the
    expected record_id.

    ``results`` maps an eval item's query -> its ranked ``[record_id, ...]`` list
    (rank 1 first). Items with no retrieved result (missing or empty list) count
    as a miss. Returns 0.0 for an empty eval set.
    """
    total = len(eval_set)
    if total == 0:
        return 0.0
    hits = 0
    for item in eval_set:
        ranked = _ranked_for(results, item)
        if ranked and ranked[0] == item.get(EVAL_EXPECTED):
            hits += 1
    return hits / total


def recall_at_k(
    results: Dict[str, Sequence[str]],
    eval_set: Sequence[Dict[str, Any]],
    k: int,
) -> float:
    """Fraction of eval items whose expected record_id appears within the top-k
    retrieved. ``k`` is clamped to >= 1. Returns 0.0 for an empty eval set.
    """
    total = len(eval_set)
    if total == 0:
        return 0.0
    kk = max(1, int(k))
    hits = 0
    for item in eval_set:
        ranked = _ranked_for(results, item)
        if item.get(EVAL_EXPECTED) in list(ranked)[:kk]:
            hits += 1
    return hits / total


def _ranked_for(
    results: Dict[str, Sequence[str]],
    item: Dict[str, Any],
) -> List[str]:
    """The ranked record_id list for an eval item's query (empty when absent)."""
    ranked = results.get(item.get(EVAL_QUERY))
    if not ranked:
        return []
    return [r for r in ranked]


def _per_query_rows(
    results: Dict[str, Sequence[str]],
    eval_set: Sequence[Dict[str, Any]],
    k: int,
) -> List[Dict[str, Any]]:
    """Per-query audit rows: what was expected, the rank-1 hit, the 0-based rank
    of the expected id within the top-k window (or None), and the retrieved
    top-k. This is the evidence trail behind the aggregate metrics (AC-3).
    """
    kk = max(1, int(k))
    rows: List[Dict[str, Any]] = []
    for item in eval_set:
        ranked = _ranked_for(results, item)
        window = ranked[:kk]
        expected = item.get(EVAL_EXPECTED)
        try:
            expected_rank = window.index(expected)
        except ValueError:
            expected_rank = None
        rows.append({
            "query": item.get(EVAL_QUERY),
            "expected": expected,
            "cluster": item.get(EVAL_CLUSTER),
            "rank1": window[0] if window else None,
            "rank1_hit": bool(window and window[0] == expected),
            "expected_rank": expected_rank,  # 0-based within top-k, or None
            "recall_hit": expected_rank is not None,
            "retrieved": window,
        })
    return rows


def capture_run(
    eval_set: Sequence[Dict[str, Any]],
    retrieve_fn: Callable[[str, int], Sequence[str]],
    k: int = DEFAULT_K,
    label: str = "before",
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the eval set through ``retrieve_fn`` and assemble a run dict.

    ``retrieve_fn(query, k) -> [record_id, ...]`` is the INJECTABLE retrieval
    surface (gamma hybrid in production; a stub in tests). Each eval item's query
    is queried once for ``k`` results.

    Run schema::

        {
          "version": "h94.v1",
          "label": "before" | "after",
          "k": <int>,
          "n": <int eval items>,
          "precision_at_1": <float>,
          "recall_at_k": <float>,
          "per_query": [ {query, expected, cluster, rank1, rank1_hit,
                          expected_rank, recall_hit, retrieved}, ... ],
          "generated_at": <null or ISO string>
        }

    ``label`` must be "before" or "after". Every metric is computed from the
    actual retrieved results — nothing is fabricated.
    """
    if label not in ("before", "after"):
        raise ValueError(f"label must be 'before' or 'after'; got {label!r}")
    kk = max(1, int(k))

    results: Dict[str, List[str]] = {}
    for item in eval_set:
        query = item.get(EVAL_QUERY)
        ranked = retrieve_fn(query, kk)
        results[query] = [r for r in ranked] if ranked else []

    p1 = precision_at_1(results, eval_set)
    rk = recall_at_k(results, eval_set, kk)
    return {
        "version": RUN_VERSION,
        "label": label,
        "k": kk,
        "n": len(eval_set),
        "precision_at_1": p1,
        "recall_at_k": rk,
        "per_query": _per_query_rows(results, eval_set, kk),
        "generated_at": generated_at,
    }


# ===========================================================================
# Verdict
# ===========================================================================
def compare(
    before_run: Optional[Dict[str, Any]],
    after_run: Optional[Dict[str, Any]],
    bar: float = DEFAULT_BAR,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Compute the precision@1 delta (after - before) and render the verdict.

    Verdict rule:
      * ``after_run`` missing / None         -> ``"baseline_only"`` with
        ``precision_at_1_after`` and ``delta`` both ``None`` (NO fabrication).
      * ``delta >= bar``                     -> ``"met"``.
      * ``delta < bar``                      -> ``"not_met"``.

    ``before_run`` is required (a verdict needs a baseline). Every reported number
    is read from the supplied captured runs; this function never synthesizes a
    metric. Returns a verdict dict (also the shape written to ``verdict.json``).
    """
    if before_run is None:
        raise ValueError("compare requires a before_run baseline")

    p1_before = _require_metric(before_run, "precision_at_1", "before_run")
    recall_before = before_run.get("recall_at_k")

    base: Dict[str, Any] = {
        "version": VERDICT_VERSION,
        "bar": float(bar),
        "precision_at_1_before": p1_before,
        "recall_at_k_before": recall_before,
        "k": before_run.get("k"),
        "n_before": before_run.get("n"),
        "generated_at": generated_at,
    }

    if after_run is None:
        base.update({
            "precision_at_1_after": None,
            "recall_at_k_after": None,
            "n_after": None,
            "delta": None,
            "verdict": VERDICT_BASELINE_ONLY,
        })
        return base

    p1_after = _require_metric(after_run, "precision_at_1", "after_run")
    delta = p1_after - p1_before
    base.update({
        "precision_at_1_after": p1_after,
        "recall_at_k_after": after_run.get("recall_at_k"),
        "n_after": after_run.get("n"),
        "delta": delta,
        "verdict": VERDICT_MET if delta >= float(bar) else VERDICT_NOT_MET,
    })
    return base


def _require_metric(run: Dict[str, Any], key: str, which: str) -> float:
    """Read a metric from a captured run, refusing to fabricate. Raises when the
    key is absent or non-numeric so a malformed run can never silently produce a
    bogus verdict number (AC-3 no-fabrication discipline)."""
    if key not in run or run[key] is None:
        raise ValueError(f"{which} is missing required captured metric {key!r}")
    val = run[key]
    if not isinstance(val, (int, float)) or isinstance(val, bool):
        raise ValueError(f"{which}.{key} must be numeric; got {val!r}")
    return float(val)


def render_summary(verdict: Dict[str, Any]) -> str:
    """Human-readable one-block summary of a verdict dict (written alongside
    verdict.json by the compare CLI)."""
    lines = [
        "ENC-TSK-H94 near-duplicate retrieval measurement (ENC-TSK-H34 AC-3)",
        f"  acceptance bar (precision@1 delta) : >= {verdict.get('bar')}",
        f"  precision@1 BEFORE (encoding OFF)  : {verdict.get('precision_at_1_before')}",
    ]
    after = verdict.get("precision_at_1_after")
    if after is None:
        lines.append("  precision@1 AFTER  (encoding ON)   : (not captured)")
        lines.append("  delta                              : (not computed)")
    else:
        lines.append(f"  precision@1 AFTER  (encoding ON)   : {after}")
        lines.append(f"  delta (after - before)             : {verdict.get('delta')}")
    lines.append(f"  recall@k BEFORE / AFTER            : "
                 f"{verdict.get('recall_at_k_before')} / {verdict.get('recall_at_k_after')}")
    lines.append(f"  VERDICT                            : {verdict.get('verdict')}")
    return "\n".join(lines)


# ===========================================================================
# Projection-liveness preflight (AC-2)
# ===========================================================================
def _extract_projection_block(health: Any) -> Optional[Dict[str, Any]]:
    """Pull the standing-projection block out of a connection_health-style dict.

    Tolerates both the MCP composite shape (``health["graph_index"]
    ["graph_projection"]``) and the raw graph-query-api health shape
    (``health["graph_projection"]``). Returns None when neither is present.
    """
    if not isinstance(health, dict):
        return None
    gi = health.get("graph_index")
    if isinstance(gi, dict) and isinstance(gi.get("graph_projection"), dict):
        return gi["graph_projection"]
    gp = health.get("graph_projection")
    if isinstance(gp, dict):
        return gp
    return None


def require_projection_live(
    health: Any,
    projection_name: Optional[str] = CANONICAL_PROJECTION_NAME,
) -> Tuple[bool, str]:
    """Inspect a connection_health-style dict's standing-projection block and
    return ``(ok, reason)``.

    ``ok`` is True only when the projection ``exists`` is true AND ``stale`` is
    false. When ``projection_name`` is provided, the block's ``name`` must also
    match it (the canonical standing projection ``gds_standing_enceladus``).
    A missing block, a missing/false ``exists``, a true ``stale``, or a name
    mismatch each yields ``ok=False`` with a specific reason.

    The health source is injectable (the CLI passes the live connection_health
    result; tests pass hand-built dicts) — this function performs NO live call.
    """
    block = _extract_projection_block(health)
    if block is None:
        return False, "no graph_projection block in health payload"

    if projection_name is not None:
        name = block.get("name")
        if name != projection_name:
            return False, (
                f"projection name mismatch: expected {projection_name!r}, "
                f"got {name!r}"
            )

    if not block.get("exists", False):
        return False, "standing projection does not exist (exists=false)"

    if block.get("stale", False):
        age = block.get("age_seconds")
        max_age = block.get("max_age_seconds")
        return False, (
            f"standing projection is stale (stale=true; age_seconds={age}, "
            f"max_age_seconds={max_age})"
        )

    return True, "standing projection live (exists=true, stale=false)"


# ===========================================================================
# Retrieval surfaces (LIVE — defensive, NOT unit-tested live)
# ===========================================================================
def _build_hybrid_event(project_id: str, query: str, top_n: int,
                        internal_key: str) -> Dict[str, Any]:
    """Synthetic API Gateway v2 (HTTP API) proxy GET event for the graph_query_api
    hybrid route, mirroring ``correlation_analysis_h91._build_vector_read_event``.

    ``requestContext.http.method == GET``, ``rawPath`` ending in ``/graphsearch``,
    ``queryStringParameters`` carrying the hybrid contract, and the lowercase
    ``x-coordination-internal-key`` header consumed by ``_authenticate``.
    """
    return {
        "version": "2.0",
        "routeKey": "GET /api/v1/tracker/graphsearch",
        "rawPath": _GRAPHSEARCH_PATH,
        "rawQueryString": (
            f"search_type=hybrid&project_id={project_id}"
            f"&query={query}&top_n={top_n}"
        ),
        "headers": {
            "x-coordination-internal-key": internal_key,
            "content-type": "application/json",
        },
        "queryStringParameters": {
            "search_type": "hybrid",
            "project_id": project_id,
            "query": query,
            "top_n": str(top_n),
        },
        "requestContext": {
            "http": {
                "method": "GET",
                "path": _GRAPHSEARCH_PATH,
                "sourceIp": "127.0.0.1",
            },
        },
        "isBase64Encoded": False,
    }


def _gamma_internal_key(lambda_client: Any, function_name: str) -> str:
    """Source the coordination internal key from the gamma function's OWN env
    (ENC-LSN-039) via ``get_function_configuration``. Returns "" when
    unavailable; the caller surfaces a clear error rather than sending an
    unauthenticated invoke."""
    try:
        cfg = lambda_client.get_function_configuration(FunctionName=function_name)
        env = (cfg.get("Environment") or {}).get("Variables") or {}
        return (
            env.get("COORDINATION_INTERNAL_API_KEY")
            or env.get("COORDINATION_INTERNAL_API_KEY_PREVIOUS")
            or ""
        )
    except Exception as exc:  # pragma: no cover - live AWS only
        print(
            f"[WARNING] could not read internal key from {function_name} env: {exc}",
            file=sys.stderr,
        )
        return ""


def _parse_invoke_payload(raw: Any) -> Dict[str, Any]:
    """Decode a Lambda invoke response Payload into the hybrid result dict,
    unwrapping the API Gateway proxy envelope ``{"statusCode","body"}`` (body is a
    JSON string). Mirrors ``correlation_analysis_h91._parse_invoke_payload``."""
    if hasattr(raw, "read"):
        raw = raw.read()
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        raw = json.loads(raw) if raw.strip() else {}
    if not isinstance(raw, dict):
        return {}
    if "body" in raw and "nodes" not in raw:
        status = raw.get("statusCode")
        body = raw.get("body")
        if isinstance(body, str):
            body = json.loads(body) if body.strip() else {}
        if isinstance(status, int) and status >= 400:
            msg = body.get("error") if isinstance(body, dict) else body
            raise RuntimeError(f"gamma hybrid returned HTTP {status}: {msg}")
        return body if isinstance(body, dict) else {}
    return raw


def _nodes_to_record_ids(body: Dict[str, Any]) -> List[str]:
    """Reduce a hybrid response body to its ranked record_id list (fused order)."""
    nodes = body.get("nodes") if isinstance(body, dict) else None
    if not isinstance(nodes, list):
        return []
    out: List[str] = []
    for n in nodes:
        if isinstance(n, dict) and n.get("record_id") is not None:
            out.append(n["record_id"])
    return out


def make_gamma_retrieve_fn(
    project_id: str = DEFAULT_PROJECT_ID,
    function_name: str = DEFAULT_GAMMA_FUNCTION,
    lambda_client: Any = None,
) -> Callable[[str, int], List[str]]:
    """Build a ``retrieve_fn(query, k) -> [record_id, ...]`` bound to the gamma
    hybrid retrieval path via direct ``lambda.invoke`` (RequestResponse).

    DEFENSIVE / NOT unit-tested against live AWS: the live run is a product-lead
    terminal job. boto3 is imported lazily; the internal key is sourced from the
    invoked function's env (ENC-LSN-039). The encoding ON/OFF state is owned by
    the function's flag env, NOT toggled here.
    """
    if lambda_client is None:
        try:
            import boto3  # lazy: keeps the module importable without boto3
            from botocore.config import Config
            lambda_client = boto3.client(
                "lambda",
                config=Config(
                    connect_timeout=5,
                    read_timeout=60,
                    retries={"max_attempts": 2, "mode": "standard"},
                ),
            )
        except Exception as exc:  # pragma: no cover - live AWS only
            raise RuntimeError(
                f"boto3 lambda client unavailable for gamma source: {exc}"
            ) from exc

    internal_key = _gamma_internal_key(lambda_client, function_name)
    if not internal_key:
        raise RuntimeError(
            "missing coordination internal key for gamma invoke; cannot source "
            "from function env (ENC-LSN-039)"
        )

    def retrieve(query: str, k: int) -> List[str]:
        event = _build_hybrid_event(project_id, str(query), int(k), internal_key)
        resp = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(event).encode("utf-8"),
        )
        if resp.get("FunctionError"):
            payload = resp.get("Payload")
            detail = payload.read().decode("utf-8") if hasattr(payload, "read") else payload
            raise RuntimeError(f"gamma invoke FunctionError: {detail}")
        body = _parse_invoke_payload(resp.get("Payload"))
        return _nodes_to_record_ids(body)

    return retrieve


def make_mcp_retrieve_fn(
    project_id: str = DEFAULT_PROJECT_ID,
    search_fn: Optional[Callable] = None,
) -> Callable[[str, int], List[str]]:
    """Build a ``retrieve_fn`` bound to the MCP hybrid graphsearch surface.

    DEFENSIVE / NOT unit-tested against live MCP. ``search_fn`` is the MCP
    code-mode ``search(action, arguments)`` callable; when omitted a best-effort
    import shim is attempted, otherwise a clear error is raised.
    """
    if search_fn is None:
        try:  # pragma: no cover - environment-specific shim
            from enceladus_mcp import search as search_fn  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "no MCP `search` callable available; pass search_fn= or run from a "
                "session where the MCP code-mode surface is bound"
            ) from exc

    def retrieve(query: str, k: int) -> List[str]:
        result = search_fn(
            action="tracker.graphsearch",
            arguments={
                "search_type": "hybrid",
                "project_id": project_id,
                "query": str(query),
                "top_n": int(k),
            },
        )
        if isinstance(result, str):
            result = json.loads(result)
        body = result if isinstance(result, dict) else {}
        if "nodes" not in body:
            for key in ("result", "data", "body"):
                inner = body.get(key)
                if isinstance(inner, str):
                    inner = json.loads(inner)
                if isinstance(inner, dict) and "nodes" in inner:
                    body = inner
                    break
        return _nodes_to_record_ids(body)

    return retrieve


def make_file_retrieve_fn(path: str) -> Callable[[str, int], List[str]]:
    """Build a ``retrieve_fn`` from a pre-captured ranked-results file
    (``--source file``). The file maps each query to its ranked record_id list:

      * ``{"results": {"<query>": ["<rid>", ...], ...}}`` or a bare
        ``{"<query>": [...]}`` object, or
      * a list of ``{"query": "...", "ranked": ["<rid>", ...]}`` rows
        (``record_ids`` / ``nodes`` accepted as aliases for ``ranked``).

    Queries absent from the file return an empty list (counted as a miss).
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    table: Dict[str, List[str]] = {}
    if isinstance(data, dict):
        results = data.get("results", data)
        if isinstance(results, dict):
            for q, ranked in results.items():
                table[q] = _coerce_ranked(ranked)
    elif isinstance(data, list):
        for row in data:
            if not isinstance(row, dict):
                continue
            q = row.get("query")
            if q is None:
                continue
            ranked = row.get("ranked")
            if ranked is None:
                ranked = row.get("record_ids")
            if ranked is None:
                ranked = row.get("nodes")
            table[q] = _coerce_ranked(ranked)

    def retrieve(query: str, k: int) -> List[str]:
        return list(table.get(query, []))[: max(1, int(k))]

    return retrieve


def _coerce_ranked(ranked: Any) -> List[str]:
    """Normalize a ranked value into a list of record_id strings. Accepts a list
    of strings or a list of ``{"record_id": ...}`` node dicts."""
    if not isinstance(ranked, list):
        return []
    out: List[str] = []
    for item in ranked:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict) and item.get("record_id") is not None:
            out.append(item["record_id"])
    return out


def build_retrieve_fn(args: argparse.Namespace) -> Callable[[str, int], List[str]]:
    """Dispatch the retrieval surface by ``--source``."""
    source = getattr(args, "source", "gamma")
    if source == "gamma":
        return make_gamma_retrieve_fn(args.project_id, args.gamma_function)
    if source == "mcp":
        return make_mcp_retrieve_fn(args.project_id)
    if source == "file":
        if not getattr(args, "results", None):
            raise ValueError("--results PATH is required for --source file")
        return make_file_retrieve_fn(args.results)
    raise ValueError(f"unknown source: {source!r}")


# ===========================================================================
# SINK helpers
# ===========================================================================
def _write_json(obj: Dict[str, Any], path: str) -> str:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)
        fh.write("\n")
    return path


# ===========================================================================
# CLI
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="measurement_harness_h94",
        description=(
            "ENC-TSK-H94 near-duplicate retrieval measurement harness "
            "(ENC-TSK-H34 AC-3): capture before/after runs and render a "
            "met/not-met precision@1 verdict against a >=5% bar."
        ),
    )
    p.add_argument("--mode", choices=["capture", "compare"], required=True,
                   help="capture a single run, or compare two captured runs.")

    # capture
    p.add_argument("--eval", dest="eval_path", default=None,
                   help="Eval-set JSON ({'eval_set':[...]} or a bare list).")
    p.add_argument("--pairs", default=None,
                   help="H91 pairs.jsonl to DERIVE an eval set (with --corpus).")
    p.add_argument("--corpus", default=None,
                   help="Corpus JSON to DERIVE an eval set (with --pairs).")
    p.add_argument("--holdout-frac", dest="holdout_frac", type=float,
                   default=DEFAULT_HOLDOUT_FRAC,
                   help="Fraction of the derived eval set to hold out (default 1.0).")
    p.add_argument("--label", choices=["before", "after"], default=None,
                   help="Run label: before (encoding OFF) or after (encoding ON).")
    p.add_argument("--k", type=int, default=DEFAULT_K,
                   help="Top-k retrieval depth (default 10).")
    p.add_argument("--source", choices=["gamma", "mcp", "file"], default="gamma",
                   help="Retrieval surface (default gamma).")
    p.add_argument("--results", default=None,
                   help="Pre-captured ranked-results file (--source file).")
    p.add_argument("--project-id", dest="project_id", default=DEFAULT_PROJECT_ID,
                   help="Project id to query (default enceladus).")
    p.add_argument("--gamma-function", dest="gamma_function",
                   default=DEFAULT_GAMMA_FUNCTION,
                   help="Gamma graph-query Lambda name.")
    p.add_argument("--require-projection", dest="require_projection",
                   action="store_true",
                   help="Abort capture unless the standing projection is live (AC-2).")
    p.add_argument("--health", dest="health_path", default=None,
                   help="connection_health JSON for --require-projection "
                        "(omit to fetch live via MCP, if bound).")

    # compare
    p.add_argument("--before", dest="before_path", default=None,
                   help="Captured before run_json (--mode compare).")
    p.add_argument("--after", dest="after_path", default=None,
                   help="Captured after run_json (--mode compare). Omit => "
                        "baseline_only verdict.")
    p.add_argument("--bar", type=float, default=DEFAULT_BAR,
                   help="precision@1 delta acceptance bar (default 0.05).")

    p.add_argument("--out", default=DEFAULT_OUT_DIR,
                   help="Output directory (default ./h94_results).")
    p.add_argument("--generated-at", dest="generated_at", default=None,
                   help="Optional ISO timestamp; datetime.now() is NEVER called.")
    return p


def _load_eval_for_capture(args: argparse.Namespace) -> List[Dict[str, Any]]:
    if args.eval_path:
        return load_eval_set_from_file(args.eval_path)
    if args.pairs and args.corpus:
        import json as _json
        with open(args.corpus, "r", encoding="utf-8") as fh:
            cdata = _json.load(fh)
        corpus = cdata.get("nodes", []) if isinstance(cdata, dict) else cdata
        pairs: List[Dict[str, Any]] = []
        with open(args.pairs, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    pairs.append(_json.loads(line))
        return build_eval_set(pairs, corpus, holdout_frac=args.holdout_frac)
    raise ValueError("capture needs --eval PATH or both --pairs and --corpus")


def _resolve_health(args: argparse.Namespace) -> Any:
    """Load a connection_health-style payload for the projection preflight. From
    --health FILE when given; otherwise a best-effort live MCP call (defensive,
    not unit-tested)."""
    if args.health_path:
        with open(args.health_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    try:  # pragma: no cover - environment-specific shim
        from enceladus_mcp import connection_health  # type: ignore
        return connection_health()
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "--require-projection set but no --health FILE and no bound MCP "
            f"connection_health(): {exc}"
        ) from exc


def _run_capture(args: argparse.Namespace) -> int:
    if args.label is None:
        print("[ERROR] --label {before,after} is required for --mode capture",
              file=sys.stderr)
        return 2

    if args.require_projection:
        try:
            health = _resolve_health(args)
        except Exception as exc:
            print(f"[ERROR] projection preflight could not load health: {exc}",
                  file=sys.stderr)
            return 2
        ok, reason = require_projection_live(health)
        if not ok:
            print(f"[ERROR] projection preflight failed (AC-2): {reason}",
                  file=sys.stderr)
            return 3
        print(f"[INFO] projection preflight OK: {reason}", file=sys.stderr)

    try:
        eval_set = _load_eval_for_capture(args)
    except Exception as exc:
        print(f"[ERROR] eval-set load failed: {exc}", file=sys.stderr)
        return 2
    if not eval_set:
        print("[ERROR] eval set is empty; nothing to measure", file=sys.stderr)
        return 2

    try:
        retrieve_fn = build_retrieve_fn(args)
    except Exception as exc:
        print(f"[ERROR] retrieval surface unavailable (source={args.source}): {exc}",
              file=sys.stderr)
        return 2

    run = capture_run(eval_set, retrieve_fn, k=args.k, label=args.label,
                      generated_at=args.generated_at)

    out_path = os.path.join(args.out, f"run_{args.label}.json")
    _write_json(run, out_path)
    run_with_path = dict(run)
    run_with_path["artifact"] = out_path
    print("MEASUREMENT_RESULTS " + json.dumps(run_with_path, default=str))
    print(
        f"[SUCCESS] captured '{run['label']}' run: n={run['n']} k={run['k']} "
        f"precision@1={run['precision_at_1']:.4f} recall@k={run['recall_at_k']:.4f} "
        f"-> {out_path}",
        file=sys.stderr,
    )
    return 0


def _run_compare(args: argparse.Namespace) -> int:
    if not args.before_path:
        print("[ERROR] --before PATH is required for --mode compare", file=sys.stderr)
        return 2
    try:
        with open(args.before_path, "r", encoding="utf-8") as fh:
            before_run = json.load(fh)
    except Exception as exc:
        print(f"[ERROR] could not load --before run: {exc}", file=sys.stderr)
        return 2

    after_run: Optional[Dict[str, Any]] = None
    if args.after_path:
        try:
            with open(args.after_path, "r", encoding="utf-8") as fh:
                after_run = json.load(fh)
        except Exception as exc:
            print(f"[ERROR] could not load --after run: {exc}", file=sys.stderr)
            return 2

    try:
        verdict = compare(before_run, after_run, bar=args.bar,
                          generated_at=args.generated_at)
    except Exception as exc:
        print(f"[ERROR] compare failed: {exc}", file=sys.stderr)
        return 2

    verdict_path = os.path.join(args.out, "verdict.json")
    summary_path = os.path.join(args.out, "verdict_summary.txt")
    summary_text = render_summary(verdict)
    _write_json(verdict, verdict_path)
    parent = os.path.dirname(os.path.abspath(summary_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as fh:
        fh.write(summary_text + "\n")

    verdict_with_path = dict(verdict)
    verdict_with_path["artifact"] = verdict_path
    print("MEASUREMENT_RESULTS " + json.dumps(verdict_with_path, default=str))
    print(summary_text, file=sys.stderr)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.mode == "capture":
        return _run_capture(args)
    if args.mode == "compare":
        return _run_compare(args)
    print(f"[ERROR] unknown mode: {args.mode!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
