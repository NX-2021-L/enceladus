# Enceladus

Enceladus is a governed, ontology-backed platform for multi-agent software engineering. AI agents and a human operator collaborate on one shared, append-only record of work — tasks, issues, features, plans, and lessons — where every change flows through a single governed tool surface, is attributed to its author, and is validated against an explicit data dictionary before it lands.

It is a personal research platform built to test two ideas in production: that **governance can be the primary architecture** of an agent system, and that a strict ontological substrate plus graph and hybrid retrieval can serve as a durable **extended mind** for the agents working inside it.

The codebase is a single monorepo: a serverless backend (AWS Lambda), the MCP server that exposes the governed tool surface, a React progressive web app, and the infrastructure-as-code and CI that deploy them.

> 🤖 **Automated agents start here:** read [`AGENTS.md`](AGENTS.md). It is the canonical agent entry point and operating contract — session initialization, the lifecycle state machine, and the governance rules every agent must follow. The rest of this README is written for humans.

## Documentation

The [`docs/`](docs/) tree is organized with the [Diátaxis](https://diataxis.fr) framework: every page is exactly one kind of documentation — explanation, reference, or how-to. Begin at the [documentation landing page](docs/README.md), or enter by what you need:

**Understand the thinking** — what was built, and why:

- [Governance as architecture](docs/explanation/governance-as-architecture.md) — the central thesis: why governance is the system's primary structure, not a bolt-on.
- [The extended mind](docs/explanation/extended-mind.md) — why the agents are given an ontological, queryable memory.
- [The v4 graph and hybrid retrieval](docs/explanation/v4-graph-and-hybrid-retrieval.md) — how durable recall is designed.

**Find the code** — locate the engineering:

- [Codebase Map](docs/reference/codebase-map.md) — each capability routed to the directories and files that implement it.
- [Architecture reference](docs/ARCHITECTURE.md) — the system described component by component.
- [MCP tool surface](docs/reference/mcp-tool-surface.md) — the governed tool API in full.

**Use it** — stand parts of it up (noncommercial):

- [Run and connect the MCP server](docs/how-to/run-and-connect-the-mcp-server.md)
- [Exercise hybrid retrieval](docs/how-to/exercise-hybrid-retrieval.md)
- [Stand up the graph projection](docs/how-to/stand-up-the-graph-projection.md)

The [documentation landing page](docs/README.md) lists everything, grouped by kind.

## Repository layout

- `backend/` — Python AWS Lambda functions and the shared runtime layer.
- `frontend/` — the React progressive web app.
- `tools/enceladus-mcp-server/` — the MCP server exposing the governed tool surface.
- `infrastructure/` — CloudFormation templates, IAM policies, and deployment metadata.
- `docs/` — all human-facing documentation (see above).

## License

Enceladus is source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE).

- **Noncommercial use is permitted** — education, academic and nonprofit research, personal study, experimentation, and other noncommercial purposes as defined by the license.
- **Commercial use requires a separate license** — production deployment, integration into a paid product or service, SaaS offerings, or use as revenue-generating infrastructure all require a negotiated commercial agreement.

For commercial licensing inquiries, contact **me@jreese.net**.

Third-party dependencies redistributed in Enceladus's built and deployed artifacts retain their own licenses; see [`NOTICE`](NOTICE) for the dependency license audit and required attributions. PolyForm-NC applies to Enceladus's first-party code and does not override those notices.
