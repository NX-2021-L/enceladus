# How to exercise hybrid retrieval

This guide shows you how to run a hybrid retrieval query against the Enceladus
graph index from a connected MCP client, how to run a relational graph search
directly, and where the keyword-only reference search fits.

It assumes you already have a working MCP client session pointed at
`https://mcp.jreese.net`. If you don't, set one up first:
[Run and connect the MCP server](./run-and-connect-the-mcp-server.md).

This is a task guide, not a design doc. For *why* hybrid retrieval fuses three
signals and how Reciprocal Rank Fusion (RRF) works internally, read
[The v4 graph and hybrid retrieval model](../explanation/v4-graph-and-hybrid-retrieval.md).
For the full parameter and return-shape reference, see
[the MCP tool surface](../reference/mcp-tool-surface.md).

## Before you begin

You need:

- A connected MCP client session (the five code-mode tools: `connection_health`,
  `search`, `execute`, `get_compact_context`, `coordination`).
- A `project_id` (for example, `enceladus`).
- Optionally, an anchor `record_id` you want results pulled toward (for example,
  a task or issue ID like `ENC-TSK-B92`).

Run `connection_health()` first to confirm the session is live before issuing
queries.

## 1. Issue a hybrid query (the primary path)

The primary way to exercise hybrid retrieval is the `get_compact_context` tool.
When you pass a `query`, an `anchor_record_id`, or both, the response gains a
`hybrid_retrieval` section in addition to the normal context payload. If you pass
neither, you get the legacy context shape unchanged.

Call it with a query, an anchor, a record-type filter, and a result cap:

```text
get_compact_context(
    mode="topic",
    project_id="enceladus",
    query="hybrid retrieval RRF fusion",
    anchor_record_id="ENC-TSK-B92",
    record_type="task",
    top_n=10,
)
```

Parameters that drive retrieval:

| Parameter | Effect |
| --- | --- |
| `query` | Free text. Enables the **vector** and **keyword** signals. |
| `anchor_record_id` | A `record_id` used as the graph anchor. Enables the **graph** signal. In record-oriented modes it defaults to `record_id` if you don't set it. |
| `record_type` | Optional filter — one of `task`, `issue`, `feature`, `plan`, `lesson`, `document`. |
| `top_n` | Final result count. Default `20`, max `50`. Applied *after* fusion and Lesson filtering. |
| `include_below_threshold` | If `true`, includes Lessons below the FSRS-6 T3 stability threshold (`0.7`). Default `false` suppresses them. |
| `include_hybrid_retrieval` | Defaults to on whenever `query` or `anchor_record_id` is set. Set `false` to suppress the section. |

You must supply at least one of `query` or `anchor_record_id`, and the call must
resolve a `project_id` (passed directly, or inferred from the anchor record or
assembled context) — otherwise the hybrid section is skipped.

### What comes back

The `hybrid_retrieval` section carries a `nodes` list ordered by fused score —
best match first — plus observability fields describing how the ranking was
produced:

```text
"hybrid_retrieval": {
    "nodes": [ ...records ordered by fused score... ],
    "signal_availability": { "vector": true, "graph": true, "keyword": true },
    "summary": "Hybrid: N nodes (vector=V, graph=G, keyword=K)"
}
```

How to read it:

- **`nodes`** is the answer — the ranked result list, best match first. Each node
  is annotated with its fused rank and per-signal ranks so you can see why it
  placed where it did.
- **`signal_availability`** tells you which of the three signals actually
  contributed. RRF fuses whatever is available — if the graph signal times out or
  the anchor isn't in the graph, you still get vector + keyword results.

The response also carries observability fields (`graph_algorithm`, `rrf_k`,
`per_node_fusion`, `duration_ms`, and the FSRS-6 threshold) for explaining or
debugging a ranking; see the [MCP tool surface](../reference/mcp-tool-surface.md)
for the full field catalog.

If every signal returns nothing, `nodes` is empty and `summary` reports
`(vector=0, graph=0, keyword=0)` with a suggestion to broaden the query or verify
the anchor is in the graph.

## 2. Run a relational graph search

When you want to walk the relationship topology directly — rather than fused
ranking — use `search` with `action="tracker.graphsearch"`. This is the
relational graph search over the Neo4j index. It supports several
`search_type` values; `hybrid` is one of them, and it returns the same fused
shape described above (`signal_availability`, `graph_algorithm`, `rrf_k`,
`per_node_fusion`, and so on).

A hybrid graph search:

```text
search(
    action="tracker.graphsearch",
    arguments={
        "project_id": "enceladus",
        "search_type": "hybrid",
        "query": "hybrid retrieval RRF fusion",
        "anchor_record_id": "ENC-TSK-B92",
        "top_n": 10,
    },
)
```

`search_type` is required and must be one of: `traversal`, `neighbors`, `path`,
`keyword`, `hybrid`. `project_id` is also required. The `anchor_record_id`,
`top_n`, and `include_below_threshold` knobs are forwarded when
`search_type="hybrid"`.

The response includes `success`, `nodes`, `edges`, `paths`, `summary`, and
`duration_ms`. If the graph index is unavailable, this returns a `GRAPH_UNAVAILABLE`
error (HTTP 503, retryable) with a hint to fall back to
`search(action="tracker.list")` or `search(action="tracker.get")` for direct
DynamoDB access.

## 3. Keyword-only reference search

To search a project's reference document text only — no vector, no graph — use
the keyword reference search:

```text
search(
    action="reference.search",
    arguments={
        "project_id": "enceladus",
        "query": "hybrid retrieval",
    },
)
```

This returns matching snippets from the reference document with line numbers and
section context — not the whole document. `project_id` and `query` are both
required; optional knobs (`regex`, `case_sensitive`, `context_lines`,
`max_results`, `section`) are catalogued in the
[MCP tool surface](../reference/mcp-tool-surface.md).

The same endpoint is reachable over HTTP at
`GET /api/v1/reference/search`, which takes the query parameters `project` and
`query` (plus the optional `regex`, `case_sensitive`, `context_lines`,
`max_results`, and `section`). Note the REST parameter names are `project` and
`query` — not `q`.

Use this path when you only need text matches in reference material and don't want
the cost or the ranking semantics of the full three-signal hybrid retrieval.

## See also

- [The v4 graph and hybrid retrieval model](../explanation/v4-graph-and-hybrid-retrieval.md) — why and how the signals are fused.
- [MCP tool surface](../reference/mcp-tool-surface.md) — full parameter and response reference.
- [Run and connect the MCP server](./run-and-connect-the-mcp-server.md) — client setup.
