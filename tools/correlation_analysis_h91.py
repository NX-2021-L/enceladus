#!/usr/bin/env python3
"""ENC-TSK-H91 — Cosine-similarity correlation analysis over the Enceladus
``n.embedding`` corpus.

Delivers ENC-TSK-H34 AC-1 and consumes the ENC-TSK-H89 / ENC-FTR-082 AC-12
governed bulk vector-read contract (graph_query_api ``search_type=vector_read``).
The emitted ``pairs.jsonl`` is the input contract for the downstream pseudoinverse
encoding (ENC-TSK-H92).

Pipeline (READ -> COMPUTE -> SINK):

  READ  ``load_corpus(args)`` returns a flat ``list[node]`` where each node is
        ``{"record_id", "record_type", "embedding": [float, ...]}``. Three
        sources:
          * ``file``  — load + concatenate nodes from a local JSON file
                        (either ``{"nodes": [...]}`` or a bare list of node
                        dicts). The only source exercised by the unit tests.
          * ``gamma`` — boto3 ``lambda.invoke`` against the gamma graph-query
                        function with a synthetic API Gateway v2 GET event for
                        ``/api/v1/tracker/graphsearch`` and
                        ``queryStringParameters={search_type:"vector_read", ...}``.
                        The ``x-coordination-internal-key`` header is sourced
                        from the invoked function's OWN env via
                        ``lambda.get_function_configuration`` (ENC-LSN-039).
                        Paginates by following ``pagination.next_offset`` until
                        ``has_more`` is false.
          * ``mcp``   — ``search(action="graph_query.vector_read",
                        arguments={project_id, offset, limit})`` with the same
                        pagination loop. Requires an injected ``search``
                        callable (the MCP code-mode surface) or an importable
                        shim; otherwise degrades with a clear error.

        NOTE: the LIVE gamma/mcp run happens later in a product-lead terminal
        against gamma. Those paths are intentionally defensive (wrapped in
        try/except, clear diagnostics) and are NOT unit-tested against a live
        service — only the ``file`` source and the pure compute/sink layers are.

  COMPUTE ``cosine_pairs(nodes, threshold)`` -> ``(pairs, stats)``. Each
        embedding is L2-normalized; pairwise cosine is computed for the upper
        triangle (i < j); pairs with cosine strictly greater than ``threshold``
        are flagged. Uses numpy (``sims = X @ X.T``) when importable for speed
        on a ~5000-node corpus, with a pure-Python (``math`` only) fallback.
        Zero-norm vectors are skipped safely.

  SINK  ``write_results(pairs, stats, args)`` mirrors the graph_query_api S3
        sink (lambda_function.py:165-176 + 1563-1590): if env
        ``CORRELATION_RESULTS_BUCKET`` is set, lazily build a tight-timeout
        boto3 S3 client and PUT ``pairs.jsonl`` + ``summary.json`` under
        ``s3://{bucket}/{prefix}/...``; ALWAYS also write both files to the
        local ``--out`` dir; and ALWAYS emit one structured stdout line
        ``CORRELATION_RESULTS {json-summary}`` (the CloudWatch-degraded mirror).
        An S3 failure is caught and never aborts the local write.

pairs.jsonl schema (one JSON object per line, sorted by cosine desc) — the
ENC-TSK-H92 input contract:

    {"a": <record_id>, "b": <record_id>,
     "a_type": <record_type>, "b_type": <record_type>,
     "cosine": <float>}
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Optional numpy. Imported once at module load; the unit tests monkeypatch this
# module attribute to None to force-exercise the pure-Python path.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - exercised indirectly
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover - numpy absent is a supported config
    np = None  # type: ignore

# Mirror graph_query_api: the read path returns the raw vector under this key.
EMBEDDING_PROPERTY = "embedding"

# Defaults that mirror the vector_read contract / governance config.
DEFAULT_PROJECT_ID = "enceladus"
DEFAULT_THRESHOLD = 0.95
DEFAULT_PAGE_LIMIT = 200
DEFAULT_OUT_DIR = "./h91_results"
DEFAULT_GAMMA_FUNCTION = "devops-graph-query-api-gamma"

# S3 sink env contract (mirrors PATHWAY_TELEMETRY_BUCKET/_PREFIX).
RESULTS_BUCKET_ENV = "CORRELATION_RESULTS_BUCKET"
RESULTS_PREFIX_ENV = "CORRELATION_RESULTS_PREFIX"
DEFAULT_RESULTS_PREFIX = "correlation-analysis-h91"

PAIRS_FILENAME = "pairs.jsonl"
SUMMARY_FILENAME = "summary.json"

_GRAPHSEARCH_PATH = "/api/v1/tracker/graphsearch"
# A high upper bound on pagination iterations so a misbehaving surface that never
# clears has_more cannot loop forever.
_MAX_PAGES = 100_000


# ===========================================================================
# READ layer
# ===========================================================================
def _coerce_nodes(payload: Any) -> List[Dict[str, Any]]:
    """Normalize a vector-read payload fragment into a list of node dicts.

    Accepts either ``{"nodes": [...]}`` or a bare ``[...]`` list. Non-dict
    members are dropped defensively.
    """
    if isinstance(payload, dict):
        nodes = payload.get("nodes", [])
    elif isinstance(payload, list):
        nodes = payload
    else:
        nodes = []
    return [n for n in nodes if isinstance(n, dict)]


def load_corpus_from_file(path: str) -> List[Dict[str, Any]]:
    """Load + concatenate nodes from a local JSON file.

    The file is either a single vector-read page ``{"nodes": [...]}``, a bare
    list of node dicts, or a list of such pages. This is the source the unit
    tests exercise.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    # A list of pages (each a dict with "nodes") vs. a bare list of nodes.
    if isinstance(data, list) and data and all(
        isinstance(item, dict) and "nodes" in item for item in data
    ):
        out: List[Dict[str, Any]] = []
        for page in data:
            out.extend(_coerce_nodes(page))
        return out
    return _coerce_nodes(data)


def _build_vector_read_event(project_id: str, offset: int, limit: int,
                             internal_key: str) -> Dict[str, Any]:
    """Construct a synthetic API Gateway v2 (HTTP API) proxy GET event for the
    graph_query_api ``vector_read`` route.

    Matches what ``lambda_handler`` expects (lambda_function.py:2182-2214):
    ``requestContext.http.method == GET``, ``rawPath`` ending in
    ``/graphsearch`` (not ``/health``), ``queryStringParameters`` carrying the
    vector_read contract, and the lowercase ``x-coordination-internal-key``
    header consumed by ``_authenticate`` (lambda_function.py:358).
    """
    return {
        "version": "2.0",
        "routeKey": "GET /api/v1/tracker/graphsearch",
        "rawPath": _GRAPHSEARCH_PATH,
        "rawQueryString": (
            f"search_type=vector_read&project_id={project_id}"
            f"&offset={offset}&limit={limit}"
        ),
        "headers": {
            "x-coordination-internal-key": internal_key,
            "content-type": "application/json",
        },
        "queryStringParameters": {
            "search_type": "vector_read",
            "project_id": project_id,
            "offset": str(offset),
            "limit": str(limit),
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
    (ENC-LSN-039) via ``get_function_configuration``.

    Returns an empty string when unavailable; the caller surfaces a clear error
    rather than silently sending an unauthenticated invoke.
    """
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
    """Decode a Lambda invoke response Payload into the vector-read result dict.

    The function returns an API Gateway proxy envelope ``{"statusCode", "body"}``
    where ``body`` is a JSON string (lambda_function.py:318-323). Tolerates an
    already-decoded dict for robustness.
    """
    if hasattr(raw, "read"):
        raw = raw.read()
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        raw = json.loads(raw) if raw.strip() else {}
    if not isinstance(raw, dict):
        return {}

    # Unwrap the proxy envelope when present.
    if "body" in raw and "nodes" not in raw:
        status = raw.get("statusCode")
        body = raw.get("body")
        if isinstance(body, str):
            body = json.loads(body) if body.strip() else {}
        if isinstance(status, int) and status >= 400:
            msg = body.get("error") if isinstance(body, dict) else body
            raise RuntimeError(f"gamma vector_read returned HTTP {status}: {msg}")
        return body if isinstance(body, dict) else {}
    return raw


def load_corpus_from_gamma(project_id: str, page_limit: int,
                           function_name: str,
                           lambda_client: Any = None) -> List[Dict[str, Any]]:
    """Paginate the gamma graph-query Lambda's ``vector_read`` path via direct
    ``lambda.invoke`` (RequestResponse).

    DEFENSIVE / NOT unit-tested against live AWS: the live run is a product-lead
    terminal job. boto3 is imported lazily; the internal key is sourced from the
    invoked function's env (ENC-LSN-039); pagination follows
    ``pagination.next_offset`` until ``has_more`` is false.
    """
    if lambda_client is None:
        try:
            import boto3  # lazy: keeps the file importable without boto3
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
            "missing coordination internal key for gamma invoke; "
            "cannot source from function env (ENC-LSN-039)"
        )

    nodes: List[Dict[str, Any]] = []
    offset = 0
    for _ in range(_MAX_PAGES):
        event = _build_vector_read_event(project_id, offset, page_limit, internal_key)
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
        nodes.extend(_coerce_nodes(body))

        pagination = body.get("pagination") if isinstance(body, dict) else None
        if not isinstance(pagination, dict) or not pagination.get("has_more"):
            break
        next_offset = pagination.get("next_offset")
        if next_offset is None:
            break
        offset = int(next_offset)

    return nodes


def load_corpus_from_mcp(project_id: str, page_limit: int,
                         search_fn: Optional[Callable] = None) -> List[Dict[str, Any]]:
    """Paginate the MCP ``graph_query.vector_read`` action.

    DEFENSIVE / NOT unit-tested against live MCP. ``search_fn`` is the MCP
    code-mode ``search(action, arguments)`` callable; when omitted this attempts
    a best-effort import shim and otherwise raises with a clear message. The MCP
    ``search`` result mirrors the vector_read body (``nodes`` + ``pagination``).
    """
    if search_fn is None:
        try:  # pragma: no cover - environment-specific shim
            from enceladus_mcp import search as search_fn  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "no MCP `search` callable available; pass search_fn= or run the "
                "live read from a session where the MCP code-mode surface is bound"
            ) from exc

    nodes: List[Dict[str, Any]] = []
    offset = 0
    for _ in range(_MAX_PAGES):
        result = search_fn(
            action="graph_query.vector_read",
            arguments={"project_id": project_id, "offset": offset, "limit": page_limit},
        )
        if isinstance(result, str):
            result = json.loads(result)
        body = result if isinstance(result, dict) else {}
        # Some MCP surfaces wrap the handler payload under "result"/"data".
        if "nodes" not in body:
            for key in ("result", "data", "body"):
                inner = body.get(key)
                if isinstance(inner, str):
                    inner = json.loads(inner)
                if isinstance(inner, dict) and "nodes" in inner:
                    body = inner
                    break

        nodes.extend(_coerce_nodes(body))
        pagination = body.get("pagination") if isinstance(body, dict) else None
        if not isinstance(pagination, dict) or not pagination.get("has_more"):
            break
        next_offset = pagination.get("next_offset")
        if next_offset is None:
            break
        offset = int(next_offset)

    return nodes


def load_corpus(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Dispatch the READ layer by ``--source``. Returns a flat list of node
    dicts ``{"record_id", "record_type", "embedding": [...]}``.
    """
    source = getattr(args, "source", "gamma")
    if source == "file":
        if not getattr(args, "input", None):
            raise ValueError("--input PATH is required for --source file")
        return load_corpus_from_file(args.input)
    if source == "gamma":
        return load_corpus_from_gamma(
            args.project_id, args.page_limit, args.gamma_function,
        )
    if source == "mcp":
        return load_corpus_from_mcp(args.project_id, args.page_limit)
    raise ValueError(f"unknown source: {source!r}")


# ===========================================================================
# COMPUTE layer
# ===========================================================================
def _valid_vectors(nodes: Sequence[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[List[float]]]:
    """Filter to nodes carrying a non-empty numeric embedding, returning the
    parallel (kept-node, vector) lists. Embeddings that are missing, empty, or
    non-numeric are dropped.
    """
    kept_nodes: List[Dict[str, Any]] = []
    vectors: List[List[float]] = []
    for n in nodes:
        emb = n.get(EMBEDDING_PROPERTY)
        if not emb or not isinstance(emb, (list, tuple)):
            continue
        try:
            vec = [float(x) for x in emb]
        except (TypeError, ValueError):
            continue
        if not vec:
            continue
        kept_nodes.append(n)
        vectors.append(vec)
    return kept_nodes, vectors


def _percentile(sorted_vals: Sequence[float], pct: float) -> Optional[float]:
    """Linear-interpolated percentile over an already-sorted ascending list.
    ``pct`` in [0, 100]. Returns None for an empty list.
    """
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    rank = (pct / 100.0) * (len(sorted_vals) - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return float(sorted_vals[lo])
    frac = rank - lo
    return float(sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac)


def _cosine_pairs_numpy(nodes: List[Dict[str, Any]], vectors: List[List[float]],
                        threshold: float) -> List[Dict[str, Any]]:
    """Vectorized upper-triangle cosine via numpy: normalize rows, ``X @ X.T``,
    flag entries above ``threshold``. Zero-norm rows are normalized to 0 so they
    contribute cosine 0 (never flagged). Used for the ~5000-node corpus.
    """
    X = np.asarray(vectors, dtype=np.float64)  # type: ignore[union-attr]
    norms = np.linalg.norm(X, axis=1, keepdims=True)  # type: ignore[union-attr]
    safe = np.where(norms == 0.0, 1.0, norms)  # type: ignore[union-attr]
    Xn = X / safe
    Xn[(norms == 0.0).ravel()] = 0.0  # zero-norm rows -> all-zero unit vector
    sims = Xn @ Xn.T

    iu, ju = np.triu_indices(len(vectors), k=1)  # type: ignore[union-attr]
    if iu.size == 0:
        return []
    sims_pairs = sims[iu, ju]
    mask = sims_pairs > threshold
    pairs: List[Dict[str, Any]] = []
    for i, j, c in zip(iu[mask].tolist(), ju[mask].tolist(), sims_pairs[mask].tolist()):
        pairs.append(_pair_record(nodes[i], nodes[j], float(c)))
    return pairs


def _cosine_pairs_python(nodes: List[Dict[str, Any]], vectors: List[List[float]],
                         threshold: float) -> List[Dict[str, Any]]:
    """Pure-Python (``math`` only) upper-triangle cosine fallback for when numpy
    is unavailable. Pre-normalizes each vector to unit L2 norm once; zero-norm
    vectors are recorded as None and skipped.
    """
    unit: List[Optional[List[float]]] = []
    for vec in vectors:
        norm = math.sqrt(sum(x * x for x in vec))
        if norm == 0.0:
            unit.append(None)
        else:
            unit.append([x / norm for x in vec])

    pairs: List[Dict[str, Any]] = []
    n = len(unit)
    for i in range(n):
        ui = unit[i]
        if ui is None:
            continue
        for j in range(i + 1, n):
            uj = unit[j]
            if uj is None:
                continue
            cos = sum(a * b for a, b in zip(ui, uj))
            if cos > threshold:
                pairs.append(_pair_record(nodes[i], nodes[j], float(cos)))
    return pairs


def _pair_record(a: Dict[str, Any], b: Dict[str, Any], cosine: float) -> Dict[str, Any]:
    """One flagged pair in the ENC-TSK-H92 input-contract shape."""
    return {
        "a": a.get("record_id"),
        "b": b.get("record_id"),
        "a_type": a.get("record_type"),
        "b_type": b.get("record_type"),
        "cosine": cosine,
    }


def cosine_pairs(nodes: Sequence[Dict[str, Any]], threshold: float,
                 generated_at: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """COMPUTE entrypoint. Normalize embeddings, compute upper-triangle cosine,
    flag pairs with cosine strictly greater than ``threshold``, and assemble
    stats.

    Returns ``(pairs, stats)`` where ``pairs`` is sorted by cosine desc. Uses
    numpy when importable, else the pure-Python fallback. ``generated_at`` is
    passed through into stats verbatim (the caller owns the clock; this function
    never calls ``datetime.now()``).
    """
    kept_nodes, vectors = _valid_vectors(nodes)

    embedding_dim = len(vectors[0]) if vectors else None
    # Defensive: drop any ragged vectors that disagree with the modal dimension
    # so the numpy matrix build cannot raise on a jagged corpus.
    if embedding_dim is not None:
        filtered = [(nd, v) for nd, v in zip(kept_nodes, vectors) if len(v) == embedding_dim]
        kept_nodes = [nd for nd, _ in filtered]
        vectors = [v for _, v in filtered]

    if len(vectors) < 2:
        pairs: List[Dict[str, Any]] = []
    elif np is not None:
        pairs = _cosine_pairs_numpy(kept_nodes, vectors, threshold)
    else:
        pairs = _cosine_pairs_python(kept_nodes, vectors, threshold)

    pairs.sort(key=lambda p: p["cosine"], reverse=True)

    flagged_cos = [p["cosine"] for p in pairs]
    involved = set()
    for p in pairs:
        involved.add(p["a"])
        involved.add(p["b"])

    sorted_flagged = sorted(flagged_cos)
    stats: Dict[str, Any] = {
        "corpus_size": len(kept_nodes),
        "embedding_dim": embedding_dim,
        "threshold": threshold,
        "num_pairs": len(pairs),
        "num_nodes_involved": len(involved),
        "max_cosine": max(flagged_cos) if flagged_cos else None,
        "mean_flagged_cosine": (sum(flagged_cos) / len(flagged_cos)) if flagged_cos else None,
        "cosine_percentiles": {
            "p50": _percentile(sorted_flagged, 50.0),
            "p90": _percentile(sorted_flagged, 90.0),
            "p99": _percentile(sorted_flagged, 99.0),
        },
        "generated_at": generated_at,
    }
    return pairs, stats


# ===========================================================================
# SINK layer
# ===========================================================================
_s3 = None


def _get_s3():
    """Lazy S3 client with tight timeouts + a single retry, mirroring
    graph_query_api ``_get_s3`` (lambda_function.py:214-231). A slow/unavailable
    S3 cannot abort the local write because the caller suppresses all errors.
    """
    global _s3
    if _s3 is None:
        import boto3
        from botocore.config import Config
        _s3 = boto3.client(
            "s3",
            config=Config(
                connect_timeout=2,
                read_timeout=5,
                retries={"max_attempts": 1, "mode": "standard"},
            ),
        )
    return _s3


def _pairs_to_jsonl(pairs: Sequence[Dict[str, Any]]) -> str:
    """Serialize pairs to newline-delimited JSON (the H92 input contract)."""
    return "".join(json.dumps(p, default=str) + "\n" for p in pairs)


def write_results(pairs: Sequence[Dict[str, Any]], stats: Dict[str, Any],
                  args: argparse.Namespace) -> Dict[str, Any]:
    """SINK entrypoint. ALWAYS writes ``pairs.jsonl`` + ``summary.json`` to the
    local ``--out`` dir and emits one structured ``CORRELATION_RESULTS {json}``
    stdout line. When ``CORRELATION_RESULTS_BUCKET`` is set, ALSO PUTs both files
    to S3 under ``{prefix}/`` — an S3 failure is caught and never aborts the
    local write.

    Returns the summary dict (the same object emitted on the stdout line),
    augmented with the artifact locations.
    """
    out_dir = getattr(args, "out", DEFAULT_OUT_DIR)
    os.makedirs(out_dir, exist_ok=True)

    pairs_path = os.path.join(out_dir, PAIRS_FILENAME)
    summary_path = os.path.join(out_dir, SUMMARY_FILENAME)

    pairs_body = _pairs_to_jsonl(pairs)
    summary_obj = dict(stats)

    # ---- Local write (always) ---------------------------------------------
    with open(pairs_path, "w", encoding="utf-8") as fh:
        fh.write(pairs_body)

    # ---- Optional S3 mirror (best-effort) ---------------------------------
    bucket = os.environ.get(RESULTS_BUCKET_ENV, "").strip()
    prefix = (os.environ.get(RESULTS_PREFIX_ENV, DEFAULT_RESULTS_PREFIX).strip()
              or DEFAULT_RESULTS_PREFIX).rstrip("/")
    s3_uris: Dict[str, str] = {}
    if bucket:
        try:
            client = _get_s3()
            pairs_key = f"{prefix}/{PAIRS_FILENAME}"
            summary_key = f"{prefix}/{SUMMARY_FILENAME}"
            client.put_object(
                Bucket=bucket, Key=pairs_key,
                Body=pairs_body.encode("utf-8"),
                ContentType="application/x-ndjson",
            )
            s3_uris = {
                "pairs": f"s3://{bucket}/{pairs_key}",
                "summary": f"s3://{bucket}/{summary_key}",
            }
            # Summary written below once s3_uris is folded in, to S3 too.
        except Exception as exc:
            print(
                f"[WARNING] correlation results S3 put failed ({exc}); "
                "local write retained",
                file=sys.stderr,
            )
            s3_uris = {}

    summary_obj["artifacts"] = {
        "pairs_local": pairs_path,
        "summary_local": summary_path,
        **({"pairs_s3": s3_uris["pairs"], "summary_s3": s3_uris["summary"]} if s3_uris else {}),
    }

    # Write the (now artifact-annotated) summary locally — always.
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary_obj, fh, indent=2, default=str)

    # Mirror the annotated summary to S3 when the pairs PUT succeeded.
    if bucket and s3_uris:
        try:
            client = _get_s3()
            client.put_object(
                Bucket=bucket, Key=f"{prefix}/{SUMMARY_FILENAME}",
                Body=json.dumps(summary_obj, default=str).encode("utf-8"),
                ContentType="application/json",
            )
        except Exception as exc:
            print(
                f"[WARNING] correlation summary S3 put failed ({exc}); "
                "local summary retained",
                file=sys.stderr,
            )

    # ---- Structured stdout line (always; CloudWatch-degraded mirror) -------
    print("CORRELATION_RESULTS " + json.dumps(summary_obj, default=str))
    return summary_obj


# ===========================================================================
# CLI
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="correlation_analysis_h91",
        description=(
            "ENC-TSK-H91 cosine-similarity correlation analysis over the "
            "Enceladus n.embedding corpus (ENC-TSK-H34 AC-1; consumes the "
            "ENC-TSK-H89 vector_read contract; emits the ENC-TSK-H92 pairs.jsonl)."
        ),
    )
    p.add_argument("--source", choices=["gamma", "mcp", "file"], default="gamma",
                   help="Corpus read surface (default: gamma).")
    p.add_argument("--input", default=None,
                   help="JSON file of {'nodes':[...]} or a bare node list (--source file).")
    p.add_argument("--project-id", dest="project_id", default=DEFAULT_PROJECT_ID,
                   help="Project id to read (default: enceladus).")
    p.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                   help="Flag pairs with cosine strictly above this (default: 0.95).")
    p.add_argument("--page-limit", dest="page_limit", type=int, default=DEFAULT_PAGE_LIMIT,
                   help="vector_read page size (default: 200).")
    p.add_argument("--out", default=DEFAULT_OUT_DIR,
                   help="Local output directory (default: ./h91_results).")
    p.add_argument("--gamma-function", dest="gamma_function", default=DEFAULT_GAMMA_FUNCTION,
                   help="Gamma graph-query Lambda name (default: devops-graph-query-api-gamma).")
    p.add_argument("--generated-at", dest="generated_at", default=None,
                   help="Optional ISO timestamp stamped into stats.generated_at.")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        nodes = load_corpus(args)
    except Exception as exc:
        print(f"[ERROR] corpus read failed (source={args.source}): {exc}", file=sys.stderr)
        return 2

    print(
        f"[INFO] loaded {len(nodes)} nodes from source={args.source}; "
        f"threshold={args.threshold}",
        file=sys.stderr,
    )

    pairs, stats = cosine_pairs(nodes, args.threshold, generated_at=args.generated_at)
    write_results(pairs, stats, args)

    print(
        f"[SUCCESS] {stats['num_pairs']} flagged pairs over "
        f"{stats['corpus_size']} embedded nodes (dim={stats['embedding_dim']})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
