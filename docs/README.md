# Enceladus documentation

This documentation is organized with the [Diátaxis](https://diataxis.fr) framework. Every page is exactly one of four kinds, because each serves a different need:

- **Explanation** answers *why* — the ideas and the design reasoning, best read away from the keyboard.
- **Reference** answers *what* — neutral, complete descriptions of the machinery, and a map from each capability to the code.
- **How-to** answers *how do I…* — directions for a competent reader with a specific goal.
- **Tutorial** answers *teach me* — a guided first lesson. Enceladus applies Diátaxis pragmatically; there is no tutorial track yet, so that kind is deliberately absent rather than stubbed out.

If you are an automated agent, your entry point is not here — it is [`AGENTS.md`](../AGENTS.md), the agent operating contract.

## Explanation — understand the thinking

The reasoning behind the system. Start here if you want to know *what was built and why*.

- [Governance as architecture](explanation/governance-as-architecture.md) — the central thesis: governance is the primary structure of the system, not a layer on top of it.
- [The extended mind](explanation/extended-mind.md) — why the agents are given an external, ontological memory, and what that buys them.
- [The v4 graph and hybrid retrieval](explanation/v4-graph-and-hybrid-retrieval.md) — the design of durable recall across vector, graph, and keyword signals.
- [The Handoff Consolidation Engine](explanation/handoff-consolidation-engine.md) — the hippocampal-replay analog that consolidates recurring Handoff patterns into proposed Lessons (HCE + GDMP provenance + FSRS-6).
- [About the MCP API boundary](explanation/about-the-mcp-api-boundary.md) — why tool handlers must go through service APIs and never touch the database directly.
- [A governance incident, retrospected](explanation/governance-incident-2026-02-27.md) — what a real production incident taught the system about its own guardrails.
- [JWT authentication forensics](explanation/jwt-authentication-forensics.md) — the analysis of a silent cross-platform build failure, and the prevention framework that came out of it.

## Reference — find the facts (and the code)

Neutral descriptions of the machinery. Consult these; you don't read them front to back.

- [Codebase Map](reference/codebase-map.md) — each major capability routed to the directories and files that implement it (the fastest way to find the engineering).
- [Architecture reference](ARCHITECTURE.md) — the system component by component (data, compute, security, frontend, operations).
- [MCP tool surface](reference/mcp-tool-surface.md) — the governed code-mode tool API and its full action registry.
- [Governance data dictionary](reference/governance-data-dictionary.md) — the ontology's fields and validation rules.
- [Repository operations](reference/repository-operations.md) — the CI workflows, guards, and maintenance scripts that build and protect the repo.
- [Session-archive spec](reference/session-archive-spec.md) — a specialized reference for the session-archive subsystem.
- [Session prompts](reference/session-prompts/) — the governed session-init templates.

## How-to — get something done

Goal-oriented directions for a reader who already has the basics.

- [Run and connect the MCP server](how-to/run-and-connect-the-mcp-server.md)
- [Exercise hybrid retrieval](how-to/exercise-hybrid-retrieval.md)
- [Stand up the graph projection](how-to/stand-up-the-graph-projection.md)
- [Build Lambda packages for the Linux runtime](how-to/build-lambda-packages-for-linux.md)
- [Back up and restore Neo4j](how-to/back-up-and-restore-neo4j.md)
- [Prove host v2 with Codex](how-to/prove-host-v2-with-codex.md)
