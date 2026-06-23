# The v4 graph and hybrid retrieval

If the [extended mind](extended-mind.md) is the goal — a governed record good enough to serve as the agents' memory — then retrieval is the mechanism that makes it real. A memory you cannot recall the right part of, at the right moment, is no memory at all. The v4 generation of Enceladus is largely the story of building that recall properly: a graph plane projected from the system of record, and a retrieval strategy that fuses three different notions of "relevant" into one ranking.

This document explains the design and the reasoning behind it. For the exact tool calls, see the [MCP tool surface](../reference/mcp-tool-surface.md); to run a query, see [how to exercise hybrid retrieval](../how-to/exercise-hybrid-retrieval.md).

## Three meanings of "relevant"

When an agent asks the record "what should I be looking at for this?", there is no single correct interpretation of relevance. There are at least three, and they disagree productively.

**Semantic relevance** is what embeddings capture: things that *mean* something similar, even with no words in common. A vector search over learned embeddings will connect "the checkout token gate" to "lifecycle advancement evidence" because they live near each other in concept space. This is powerful and lossy in the same breath — it surfaces the thematically related and, sometimes, the merely vibes-adjacent.

**Relational relevance** is what the graph captures: things that are *actually connected* to what you are working on. The task that blocks this one, the feature it serves, the issue it duplicates, the lesson learned the last time this file was touched. These relationships were named deliberately when the records were created, so they are precise in a way similarity scores never are. The task blocking your release is relevant whether or not its description sounds anything like yours.

**Lexical relevance** is what keyword matching captures: the exact term. When an agent searches for `ENC-ISS-313` or "PolyForm" or a specific function name, it does not want the semantically-nearby — it wants the literal hit. Embeddings famously blur exactly the precise tokens that keyword search nails.

Each signal is strong where the others are weak. The design conclusion writes itself: do not choose. Run all three and fuse them.

## The graph plane, and why it is disposable

To make relational relevance available, v4 adds a graph projection of the record. DynamoDB remains the **single source of truth** — every task, edge, and status lives there authoritatively. The graph (a Neo4j instance) is a *derived* view: a streaming pipeline carries each change from the DynamoDB stream, through an event pipe and a debouncing queue, into a sync process that maintains the corresponding nodes and typed edges in the graph.

The most important property of this arrangement is that the graph is **disposable**. It can be rebuilt from the source of truth at any time, and — decisively — if it is unavailable, *nothing upstream breaks*. Writes still land, lifecycles still advance, the system still functions. The graph makes retrieval better; it is never on the critical path of correctness. This is a deliberate resilience choice: the expensive, stateful, externally-hosted component is precisely the one the system is designed to survive losing.

On top of the graph sits a standing projection used for ranking — a precomputed structure that lets the system run Personalized PageRank (relevance as "importance, as seen from where you are standing") cheaply, refreshed on demand rather than held hot. When the projection is absent or stale, retrieval falls back to direct graph traversal. Recall degrades gracefully; it does not fail.

## Reciprocal Rank Fusion: combining without calibrating

Having three rankings, the question is how to merge them. The tempting answer — normalize each signal's scores and add them — is a trap, because the scores are not commensurable. A cosine similarity of 0.82, a PageRank weight, and a keyword match count do not live on the same scale, and forcing them onto one requires calibration that drifts the moment the data does.

Enceladus uses **Reciprocal Rank Fusion** instead. RRF throws away the scores and keeps only the *ranks*: an item's fused score is the sum, across the three signals, of one over its position in that signal's list (offset by a constant). An item ranked first by the graph, eighth by vectors, and absent from keywords still scores well; an item that all three rank highly dominates. The method is almost embarrassingly simple, has one well-understood constant, and — crucially — needs no per-signal calibration and no training. It is robust precisely because it asks each signal only the question that signal answers reliably: *is this near the top of your list?*

This is a recurring taste in the codebase: prefer the mechanism that stays correct as the world shifts over the one that is theoretically optimal under assumptions that won't hold next month.

## Consolidation: not all memory is equal

Retrieval is also where the [lesson](extended-mind.md) consolidation surfaces. Lessons carry a stability value from a spaced-repetition model, and below a threshold a lesson is treated as not-yet-trustworthy and held back from default results. The effect is that the memory the system offers up is the *reinforced* memory — the things that have proven true more than once — rather than every half-formed note an agent ever left. Recall is filtered through confidence, which is what keeps a growing record from becoming a louder record.

## The cost discipline

A note on economics, because it shaped the design as much as any algorithm. The graph runs on a free-tier instance, woken on demand; the standing projection is refreshed rather than kept warm; embeddings are computed once and stored. None of this is incidental. A retrieval system that quietly accrues a large fixed monthly cost is a retrieval system that will, eventually, be turned off. Building it to be cheap *at rest* — to cost almost nothing when no one is querying — is what lets it stay on indefinitely, which is the only way an external memory earns the "reliably available" status the [extended mind](extended-mind.md) requires. Frugality here is not penny-pinching; it is a reliability property.

## What it adds up to

The v4 retrieval design is three honest signals, fused by ranks rather than calibrated scores, over a disposable graph that the system is built to survive, filtered through a model of which memories have earned trust, and kept cheap enough to leave running forever. Each of those choices trades a little theoretical peak performance for robustness, resilience, or cost. That trade — *good and durable* over *optimal and fragile* — is the through-line of the whole platform.
