# DOC-6EFD5DB32CD8 — Enceladus v4: Greenfield Architecture and Migration Blueprint

**Project**: enceladus
**Author**: J. Reese (via Claude — Gamma Session, April 2026)
**Created**: 2026-04-03
**Revised**: 2026-04-22 (Revision 5)
**Status**: Living Document
**Related**: ENC-PLN-006, ENC-PLN-003, ENC-ISS-149, ENC-ISS-150, ENC-ISS-180, DOC-E470AC8CE9A8, ENC-FTR-047, ENC-FTR-049, ENC-FTR-050, ENC-FTR-052, ENC-FTR-054, ENC-FTR-055, DOC-157A790F9E8B, ENC-FTR-076, ENC-FTR-093, ENC-FTR-094, DOC-E2379D980FA2, DOC-73FF5950DA61, ENC-FTR-095, ENC-FTR-096, DOC-D3EA86857600

---

**Revision history.** Revision 1: initial blueprint (2026-04-03). Revision 2: added Pre-Flight Prerequisites, Risk Registry, hardened phase gates, and ENC-ISS-180 design constraint (2026-04-07). Revision 3 (2026-04-22): integrated component ontological hardening decisions from DOC-157A790F9E8B — revised component definition to the injection-pair model with five formal invariants, replaced deprecated transition_type enum, updated §II/III/VII/VIII for consistency, fixed compliance violations throughout. Revision 4 (2026-04-22): updated §VIII with empirical 𝔈/𝔇 anchors (F11–F16), K_eff kernel definition, memory consolidation as fifth architectural principle, sheaf cohomology → I1–I5 connection, memory consolidation Lambda in Phase 5, symbol fix (double-struck → Fraktur), added DOC-E2379D980FA2 and DOC-73FF5950DA61. Revision 5 (2026-04-22): ENC-FTR-095 (Sheaf Laplacian H¹ Detection) and ENC-FTR-096 (Memory Consolidation Lambda) created as governed feature records and added as ENC-PLN-006 objectives; tracker IDs integrated into §VII and §VIII references throughout; both added to Related.

---

## Executive Summary

Enceladus is entering v4 from a position of genuine architectural advantage — not just relative to where it started, but relative to the 120+ agentic AI tools now mapped across 11 categories in the Q1 2026 landscape. The platform's governance primitives (checkout service, transition_type_matrix, constitutional scoring, governance hash) are not features that can be bolted on; they are structural commitments that take years to develop correctly. No other platform in the current landscape possesses this combination.

The v4 thesis is unchanged: surgical decomposition of tracker_mutation, introduction of vector embeddings into context assembly, and hardening of the MCP surface. What has sharpened since the initial blueprint is the strategic framing, the risk profile, the sequencing logic, and — as of 2026-04-22 — the ontological definition of a component and the institutional memory consolidation arc. The market is moving fast — Deloitte predicts 33% of enterprise software will include agentic AI by 2028, and the governance gap is now explicitly recognized as a competitive differentiator. Enceladus is positioned to claim that gap.

This document (Revision 5) supersedes all prior framing on component identity, transition_type semantics, phase prerequisite gates, and the architectural philosophy of memory in §VIII, incorporating the ontological hardening decisions of DOC-157A790F9E8B, the mathematical grounding of DOC-E2379D980FA2 and DOC-73FF5950DA61, and the formal feature records ENC-FTR-095 and ENC-FTR-096 now locked into ENC-PLN-006 as objectives.

The migration remains phased across twelve weeks. Total new monthly cost: approximately $1.50–5. The constraint is still the moat.

---

## I. Competitive Landscape and Differentiation Analysis

### The Market Has Confirmed the Whitespace — and Named It

The Q1 2026 competitive landscape analysis across 120+ agentic AI tools spanning 11 categories (frameworks, orchestration platforms, MCP servers, gateways, memory systems, observability tools, foundation models, enterprise platforms, security tools, dev tools, and APIs) confirms the original finding: no platform combines multi-project work tracking, a knowledge graph, and AI agent governance with constitutional scoring in a single system. This is genuine, defensible whitespace.

More importantly, the market has now named the category Enceladus is pioneering. Analyst firms are calling it "bounded autonomy architecture" — systems with clear operational limits, escalation paths to humans for high-stakes decisions, and comprehensive audit trails of agent actions. Deloitte describes the emerging organizational model as "human-on-the-loop" orchestration, where humans set policy and review outcomes rather than approving every action. Enceladus's checkout service with CAI/CCI tokens is a textbook implementation of this model: agents execute autonomously within the transition_type_matrix but cannot cross stage boundaries without earning a governance token.

**Revision 3 note:** The external-positioning framing of "bounded autonomy" and "human-on-the-loop" is accurate as market language for external audiences. Internally, the governing framing per ENC-PLN-006 (updated 2026-04-04) is the extended mind architecture: Enceladus is constitutively part of io's cognitive process, not merely infrastructure. Human IS the loop's origin. The external and internal framings are complementary, not contradictory.

### The 2026 Competitive Landscape

The following platforms define the competitive field as of Q1 2026, each with a characterizing strength and the gap relative to Enceladus.

LangGraph (framework): graph-based orchestration at 126K+ stars; zero project tracking, no lifecycle governance. CrewAI (framework): role-based crews with fast onboarding; ceiling at 6–12 months, no knowledge management. OpenAI Agents SDK (framework): tight GPT-4o integration with Swarm lineage; framework-locked, no cross-provider governance. Google ADK (framework): Gemini-native multi-agent support; Google ecosystem only, no work lifecycle tracking. Anthropic Agent SDK (framework): Claude-native tool use; no governance layer beyond tool calling. Dify (platform): visual workflow builder with RAG; no lifecycle gates or transition enforcement. Notion 3.0 (platform): AI agents across pages up to 20 minutes; no checkout tokens, transition matrices, or constitutional scoring. MintMCP and ContextForge (MCP gateway): centralized tool governance and audit trails; tool access only, no work lifecycle, no knowledge graph. Palantir AIP (enterprise): ontology-powered at enterprise scale; requires Palantir infrastructure, no serverless economics. LangSmith and Langfuse (observability): trace-level visibility into agent calls; observability only, no work tracking or lifecycle governance. Credo AI (governance): enterprise model compliance for bias and drift; model-level only, not task-lifecycle governance. ServiceNow AI (enterprise): end-to-end IT and HR workflows with AI Control Tower; requires ServiceNow platform investment, not agentic-native.

### A New Category: MCP Gateways

An emerging infrastructure layer — MCP gateways — has crystallized as a distinct category in early 2026. Solutions like ContextForge, MintMCP, Peta, TrueFoundry, and WSO2's AI Gateway centralize authentication, authorization, audit logging, and policy enforcement for AI agent tool access. These are described as "smart brokers" between AI clients and MCP servers.

Enceladus's combination of the coordination API, the MCP server, and the checkout service collectively implement a more sophisticated version of what these gateways provide — and uniquely pair it with work lifecycle management and institutional knowledge. The distinction matters for positioning: Enceladus is not competing with MCP gateways, it subsumes their core value proposition while adding everything they lack.

In external positioning, Enceladus should be framed as "the only governed MCP platform that tracks work, enforces lifecycle, and builds institutional memory."

### Enceladus's Protected Differentiators

These capabilities must be treated as inviolable architectural commitments in v4. They are not implementation details — they are the product.

First, the checkout service with CAI/CCI tokens implementing bounded autonomy at the task level. The transition_type_matrix is a state machine that agents cannot bypass. This is the most architecturally unique primitive across all 120+ researched tools.

Second, constitutional scoring for lessons with evidence-gated, append-only records, four-pillar scoring, and governance amendment proposals. No equivalent exists. As the EU AI Act matures, this kind of structured auditability will become a compliance requirement, not just a nice-to-have.

Third, the Context Node primitive implementing greedy knapsack context packing within token budgets. Gartner predicts "context engineering" will appear in 80% of AI tools by 2028. Enceladus is already engineering it at the infrastructure level.

Fourth, three-signal hybrid retrieval (vector similarity + graph traversal + keyword RRF) achieving approximately 87% retrieval accuracy versus 65% for basic retrieval. Enabled by Neo4j's native HNSW vector indexing on AuraDB Free — zero incremental infrastructure cost.

Fifth, serverless economics at $30–40/month across 21 projects, 20 Lambda functions, graph search, MCP server, and multi-provider coordination. This is 100–1000x cheaper than enterprise alternatives at equivalent capability. The constraint is the moat.

### Acknowledged Gaps (Not v4 Priorities)

Enceladus lacks a visual workflow builder, sophisticated multi-agent conversation patterns, mature RAG pipeline connectors, and any form of distributed tracing or observability dashboards. These are acknowledged, monitored gaps. The v4 differentiation is governance depth, not breadth.

One exception: minimum viable observability (AWS X-Ray traces + CloudWatch dashboards) should be addressed in Phase 5, not deferred to v5. Operating four new Lambda services across a 12-week migration window without distributed tracing is an operational risk, not just a feature gap.

### Protocol Intelligence: MCP and A2A

MCP has won decisively — 97M+ monthly SDK downloads, adopted by Anthropic, OpenAI, Google, Microsoft, and AWS. Enceladus should continue investing exclusively in MCP.

A2A (Google's Agent-to-Agent Protocol) should be classified as a monitored risk rather than a dismissed non-priority. Enterprise adoption data from Q1 2026 shows A2A gaining traction in regulated industries alongside MCP, not replacing it. Enceladus does not need to implement A2A in v4, but should maintain an architectural seam in the coordination API that can accommodate an A2A adapter without structural changes.

---

## II. Current Architecture Assessment

### What Works (Preserve in v4)

DynamoDB-as-source-of-truth with Neo4j-as-derived-projection is a sophisticated dual-store pattern most platforms don't attempt. The authoritative-source/derived-projection distinction is critical: Neo4j can be rebuilt from DynamoDB at any time, which provides recovery options that peer-to-peer graph databases lack.

The governance hash (SHA-256 optimistic concurrency) provides write consistency without distributed locks. Simple, auditable, robust across all service boundaries.

SQS FIFO debounce for feed generation is a clean solution for preventing redundant work. Already a form of CQRS. Preserve and extend this pattern.

The multi-provider coordination API is a lightweight, pragmatic dispatch to Claude, Codex, and Bedrock with session tracking. One of the few neutral multi-provider coordination layers in the ecosystem.

The five code-mode meta-tools are the right abstraction layer. Keep them. The token savings they provide (75–85%) are a structural advantage, not an optimization.

Plan and Lesson primitives (ENC-FTR-058, ENC-FTR-052) are first-class governed records with their own lifecycle contracts. These are recent additions that materially expand Enceladus's institutional memory model. v4 builds on them.

### What's Straining (Address in v4)

tracker_mutation is a monolith hiding inside a Lambda. It handles record CRUD, lifecycle enforcement, checkout service interactions, constitutional scoring, component registry lookups, and relationship management in a single function. This creates a blast radius problem: a scoring bug can take down basic task creation. It also makes the codebase increasingly difficult for agents to reason about during development sessions — a real cost when agents are both users and builders.

server.py is a meta-router that should be a meta-dispatcher. The single-file MCP server routing all 50+ raw operations through 5 code-mode tools works at current scale but creates a deployment bottleneck: any change to any tool requires redeploying the entire MCP surface, and a bug in one handler can affect all five tools.

The single devops-project-tracker table creates noisy neighbor risk and prevents per-type operational tuning. The fix is targeted: extract relationships and retain everything else.

No vector embeddings is the most impactful gap. Context assembly using only keyword + RRF scoring misses semantic relationships that are obvious to humans. Hybrid retrieval (vector + graph + keyword) achieves approximately 87% accuracy versus 65% for basic retrieval. The fix is low-cost and Phase 1.

Plan and Lesson records have no graph projection. The graph_sync Lambda does not project plan or lesson nodes to Neo4j. This means the platform's own migration work (tracked as plans) cannot be graph-traversed, and institutional memory (lessons) is invisible to relational context assembly. This is a bootstrapping problem that Phase 1 must fix as its first deliverable.

The auth surface has accumulated complexity debt. ENC-LSN-011 documents auth/session failures as the #1 cross-project issue class with 10+ incidents. ENC-LSN-007 notes that auth bugs always have 3+ interacting root causes. Two P1 auth issues remain open: ENC-ISS-125 (Codex 401) and ENC-ISS-070 (Claude Connector token). Adding new auth surfaces before resolving existing debt will compound the failure rate.

### What's Now Resolved: Post-April 2026 Ontological Hardening (Revision 3)

As of 2026-04-22, DOC-157A790F9E8B establishes a materially revised definition of what an Enceladus component is, with downstream consequences for every phase of this migration.

**Component identity.** A component is no longer just a named governance primitive. It is formally the smallest bounded tuple of (i) a physically-realized, universally-addressable, externally-verifiable runtime resource and (ii) a uniquely-authoritative repository source location from which that runtime resource is produced. Identity is carried by an injection-pair `(component_address, component_repo_dir)` satisfying five formal invariants: address injection (I1), source injection (I2), source non-overlap (I3), source specificity (I4), and source exhaustiveness over deploy code (I5). The `component_id` field is now an index, not an identity.

**New required fields.** Every component record must carry four new fields: `component_address` (the universally unique runtime address — ARN, HTTPS URL, Cloudflare resource ID, Neo4j AuraDB URI, or meta sentinel), `component_repo_dir` (the MECE repo path slice, antichain under prefix order), `component_address_class` (one of `aws_arn`, `https_url`, `cloudflare_resource`, `neo4j_auradb`, `external_manifest`, `meta`), and `component_class` (one of `physical`, `external`, `meta`).

**Revised transition_type enum.** The legacy enum (`github_pr_deploy`, `lambda_deploy`, `web_deploy`, `no_code`, `data_only`) is fully deprecated as of 2026-04-22. The v3 enum is `{code, external_deploy, documentation}`. `no_code` is deprecated outright — every task must produce either a repo artifact or a docstore artifact (the Artifact-Genesis Corollary). Any remaining references to `no_code` or `data_only` in this document or in tracker records are governance debt; migration to the v3 enum is gated on H-SCHEMA shipping, after which server-side enforcement will reject the legacy values.

**Structural tensions in the current prod surface.** Five decomposition problems exist in the current component registry that cannot satisfy I1–I5 without action: T1 (MCP shared-source: `enceladus-mcp-code` and `enceladus-mcp-streamable` share `server.py`; deferred to ENC-FTR-094 gamma-first), T2 (PWA conflates S3 + CloudFront ARNs and two source paths; resolved in H-BACKFILL via three-component split), T3 (Neo4j AuraDB is external, not in AWS; registered as `component_class=external` with manifest at `infrastructure/external/neo4j-auradb.yaml`), T4 (CloudFormation-managed resources; v1 umbrella-per-CFn-file per O1, full split deferred to ENC-FTR-093), and T5 (meta umbrella renamed from `comp-umbrella-no-code` to `comp-umbrella-governance-documentation` with `required_transition_type=documentation`).

**Three new workstreams under ENC-PLN-040.** H-SCHEMA (schema fields, evidence sub-schemas, P1–P7 preconditions, deprecation Lesson), H-BACKFILL (populate all existing components with hardening fields, decompose T2/T3/T4/T5, migrate transition_type records), and H-DRIFT (D1–D4 daily drift audit in `enceladus-governance-audit`). These workstreams augment ENC-PLN-040 and introduce phase-gate dependencies into this plan (see §VII).

---

## III. Greenfield Architecture Blueprint

### Service Boundary Decomposition

The tracker_mutation Lambda splits into four focused services, decomposed along trust and responsibility boundaries — not technology boundaries.

Record Service handles all CRUD operations for tasks, issues, features, plans, lessons, and relationships. This is the hot path. It validates input, enforces schema, generates record IDs, and writes to DynamoDB. It publishes mutation events to an SNS topic for downstream consumers. Record Service does not know about lifecycle rules; it publishes events and trusts that lifecycle validation has already been applied by the caller.

Lifecycle Service owns the transition_type_matrix and all status transition logic. It validates that a requested status transition is legal given current state, component strictness, subtask gates, and checkout status. It is invoked synchronously by Record Service (or Checkout Service) before any status write occurs. The component enforcement logic (STRICTNESS_RANK ordering, no-components block) and subtask gate enforcement belong here. This service can evolve independently — new transition types, new matrix versions, new gate rules — without touching Record Service or Checkout Service.

Checkout Service remains its own Lambda (it already is) and gains clearer boundaries. It owns CAI/CCI token lifecycle, advance requests, the transition_type integrity check (the B08 stamp-at-checkout pattern), and worktree session tracking. It must not contain any record CRUD logic. It calls Lifecycle Service for transition validation, then calls Record Service to write the result. Note: the advance-time preconditions P6 (`external_deploy_evidence` shape) and P7 (`documentation_evidence` novelty-or-freshness close-gate) from DOC-157A790F9E8B live in checkout_service, not in Lifecycle Service.

Scoring Service handles constitutional scoring for lessons asynchronously. Triggered by SNS when a lesson is created or updated, it scores against the four pillars and vibe board, then writes results back to DynamoDB via Record Service. This removes a computationally expensive and evolvable operation from the synchronous write path. The lesson record receives an immediate `scoring_status: pending` field, updated to `scored` when Scoring Service completes. This decoupling enables future ML-based scoring without affecting the hot path.

The MCP server remains a meta-router but decomposes from a single file into a modular package structure. The 5 code-mode meta-tools are the right abstraction — keep them. Internally, each tool dispatches to a focused handler module. The MCP server's role is context assembly and tool routing, not business logic. Note: `server.py` is a known T1 shared-source tension (DOC-157A790F9E8B §3.5). Until ENC-FTR-094 closes, the MCP duo is registered as a single umbrella component with a known-debt note; no clean 1:1 component-to-source mapping exists for this Lambda pair until the gamma-first refactor.

CQRS is adopted lightly. Write operations flow through Record Service → Lifecycle Service. Read operations flow through a dedicated Read API that queries DynamoDB directly (simple lookups) or Neo4j (graph traversal, vector similarity, hybrid context assembly). The existing feed generation pattern (SQS FIFO debounce → pre-computed S3 → CloudFront) is already CQRS and is preserved.

### Component Registry Model (v3 — Revised)

Every new service introduced in this migration must be registered in the component registry using the v3 schema. The following mapping applies to the four new v4 Lambda services.

Record Service: `component_address` = `arn:aws:lambda:us-east-1:{account}:function:enceladus-record-service`, `component_address_class` = `aws_arn`, `component_class` = `physical`, `component_repo_dir` = `backend/lambda/record_service`, `required_transition_type` = `code`.

Lifecycle Service: `component_address` = `arn:aws:lambda:us-east-1:{account}:function:enceladus-lifecycle-service`, `component_address_class` = `aws_arn`, `component_class` = `physical`, `component_repo_dir` = `backend/lambda/lifecycle_service`, `required_transition_type` = `code`.

Scoring Service: `component_address` = `arn:aws:lambda:us-east-1:{account}:function:enceladus-scoring-service`, `component_address_class` = `aws_arn`, `component_class` = `physical`, `component_repo_dir` = `backend/lambda/scoring_service`, `required_transition_type` = `code`.

Read API: `component_address` = `arn:aws:lambda:us-east-1:{account}:function:enceladus-read-api`, `component_address_class` = `aws_arn`, `component_class` = `physical`, `component_repo_dir` = `backend/lambda/read_api`, `required_transition_type` = `code`.

All four use `component_class=physical` and `required_transition_type=code` per the default mapping from `aws_arn` address class. The propose-time preconditions P1–P5 (address uniqueness, address verifiability, repo-dir existence, repo-dir non-overlap, transition-type/address-class compatibility) are enforced server-side once H-SCHEMA lands. These components cannot be proposed until H-SCHEMA is in-flight.

For the existing prod decomposition tensions: T2 (PWA three-way split to `comp-enceladus-pwa-frontend`, `comp-enceladus-pwa-cdn`, `comp-enceladus-api-gateway`) and T3 (Neo4j as `comp-enceladus-neo4j` with `component_class=external`, `component_address_class=neo4j_auradb`, `required_transition_type=external_deploy`) are executed in H-BACKFILL. T4 umbrella-per-CFn-file registration also executes in H-BACKFILL. T1 (MCP shared-source) is deferred to ENC-FTR-094. Full schema and worked examples in DOC-157A790F9E8B §4.

### Data Layer Architecture

Retain single-table design for core tracker records (tasks, issues, features, plans, lessons) — these are queried together and benefit from capacity pooling. Extract operationally distinct data.

Relationships (rel# SK prefix) migrate to a dedicated `enceladus-relationships` table for independent Stream processing and reduced scan noise. Migrated in Phase 4 via dual-write. Context-nodes table (already planned in ENC-FTR-050 CloudFormation spec) is correctly separated. Checkout-tokens table is correctly separated.

Neo4j AuraDB Free remains the graph backend. Free tier limits have expanded to 200K nodes / 400K relationships. At approximately 2,789 records projecting to 50K with 3–5 relationships each, Free tier provides ample headroom. Native HNSW vector index support enables full hybrid retrieval at zero additional cost.

Neo4j is also now a registered `component_class=external` component (`comp-enceladus-neo4j`) as per T3 resolution in DOC-157A790F9E8B. Changes to the AuraDB instance (tier upgrade, connection config rotation) are governed as `required_transition_type=external_deploy` advances with `external_deploy_evidence` containing the AuraDB instance ID and machine-reproducible retrieval steps.

Graph backup strategy (required, not optional): Neo4j AuraDB Free has no SLA and no automated backup. Mitigation: implement a daily automated APOC export to S3 via a scheduled Lambda. Document the rebuild procedure from DynamoDB as the authoritative source. The graph should be rebuildable from scratch within 15 minutes from DynamoDB Streams replay.

Migration target if Free tier is outgrown: FalkorDB self-hosted on a t4g.small EC2 instance ($12–15/month). OpenCypher-compatible; Cypher queries transfer with minimal changes. Neptune Serverless ($80/month minimum, never scales to zero) is not viable.

### The Vector Embedding Layer

Add Amazon Titan Embeddings V2 (256 dimensions, $0.02/million tokens) via Bedrock.

One-time batch embedding of all approximately 2,789 records: approximately $0.03. Ongoing embedding on every record update: approximately $0.03/month. Total: essentially free.

The embedding pipeline piggybacks on the existing DynamoDB Streams → Lambda sync: record mutation triggers DynamoDB Stream; graph sync Lambda calls Bedrock Titan V2 to generate a 256-dimensional embedding; Lambda writes the embedding as a vector property on the Neo4j node AND as a binary attribute on the DynamoDB item (dual-store ensures durability); context assembly uses a single Neo4j Cypher query: vector similarity entry points → graph traversal expansion → keyword RRF → greedy knapsack packing.

This delivers three-signal hybrid retrieval: vector similarity (semantic relevance), graph traversal (relationship context), keyword matching (exact precision). Combined with the existing greedy knapsack packer, this is the crown jewel of v4 context assembly.

### v4 Service Map

API Layer: HTTP API v2 routes to Lambda functions for all CRUD and query operations. A separate REST API Gateway endpoint handles the MCP Streamable HTTP transport with response streaming enabled. CloudFront sits in front of both, with Lambda@Edge handling JWT validation for authenticated routes.

Write Path: API Gateway → Record Service Lambda → DynamoDB write → SNS mutation event → fanout to Lifecycle validation, Graph sync + embedding, Context node update, Feed debounce queue.

Read Path: API Gateway → Read API Lambda → DynamoDB (simple lookups) or Neo4j (graph traversal, vector similarity, hybrid context assembly). CloudFront caches GET responses where appropriate.

MCP Surface: REST API Gateway (streaming) → MCP Server Lambda (provisioned concurrency, 1 instance) → dispatches to handler modules → calls Read API for context assembly, Record Service for mutations, Coordination API for dispatch.

Async Services: Scoring Service (SNS-triggered, constitutional scoring), Feed Publisher (SQS FIFO debounced), Graph Sync (DynamoDB Streams via EventBridge Pipes → Lambda → Neo4j + Bedrock embeddings → vector index update), Context Node Sync (DynamoDB Streams → Lambda → context-nodes table).

Coordination Layer: Coordination API Lambda handles multi-provider dispatch (Claude Agent SDK, OpenAI Agents SDK, Google ADK, Bedrock Agent), session tracking, callback processing, and intake debounce. Each provider integration is implemented as a provider adapter behind a common contract interface — preventing framework-specific SDK calls from leaking into the coordination layer's core logic.

---

## IV. Investment Recommendations: Heavier vs. Lighter

### Go Heavier on These Five Areas

First, provisioned concurrency for the MCP server Lambda. One provisioned instance at 512MB ARM64 costs approximately $1.50/month and eliminates cold starts entirely for the most latency-sensitive endpoint in the system. Highest ROI investment available.

Second, vector embeddings in context assembly. Adding Titan V2 embeddings stored in Neo4j's native vector index transforms context assembly from keyword-only to hybrid three-signal retrieval. Cost: approximately $0.03/month. Impact: approximately 87% vs. approximately 65% retrieval accuracy.

Third, Lambda SnapStart + ARM64 across all functions. Enable SnapStart on all Python 3.12+ Lambda functions (90% cold start reduction, free) and switch all functions to ARM64/Graviton (20% cost savings, 13–24% faster initialization). Zero-cost wins. Apply universally.

Fourth, REST API Gateway for the MCP streaming endpoint. HTTP API v2 does not support response streaming. Migrate the MCP endpoint specifically to REST API Gateway with `responseTransferMode: STREAM`, enabling SSE for long-running tool calls. Enables 500ms TTFB versus 8–10 seconds buffered, with 15-minute timeout and 200MB payload limit.

Fifth, the Scoring Service as an independent, asynchronous service. Moving constitutional scoring off the write path enables future ML-based scoring evolution without touching the hot path. The scoring_status: pending field provides immediate feedback to callers without blocking.

### Go Lighter on These Five Areas

First, eliminate Lambda glue code with EventBridge Pipes. Replace DynamoDB Streams → Lambda → EventBridge patterns with DynamoDB Streams → EventBridge Pipes → targets. Each Pipe replacement eliminates one Lambda function and reduces operational surface area.

Second, bifurcate auth strategy immediately. For agent clients (Codex, Bedrock Agent, Anthropic Agent SDK), use API key authentication. These clients don't need browser redirects. The redirect_mismatch bugs documented in ENC-ISS-124/125 stem from forcing OAuth flows where they're unnecessary. Keep Cognito OAuth only for interactive clients (Claude.ai web/mobile/desktop, PWA). This immediately resolves the majority of recurring auth failures.

Third, CloudFront Functions cannot replace Lambda@Edge for auth. CloudFront Functions lack asymmetric crypto support and cannot validate RS256 JWTs. Keep Lambda@Edge but optimize it: cache JWKS keys and embed the public key directly rather than fetching on each request.

Fourth, do not add DAX, ElastiCache, or any managed caching layer. DAX minimum is approximately $194/month (single node), ElastiCache Serverless minimum is approximately $60/month. Both require VPC configuration. Use the three-tier free caching strategy instead: CloudFront caching, in-Lambda execution environment caching, S3 pre-computed responses.

Fifth, consolidate SNS topics where appropriate. Keep EventBridge for content-based routing. Evaluate whether the current SNS topics can be consolidated — single-subscriber topics should be replaced with direct Lambda invocations or Pipes targets.

---

## V. Pre-Flight Prerequisites

Before Phase 0 of the v4 migration begins, the following conditions must be true. These are not nice-to-haves — they are gate requirements.

### Hard Gates (Must Be Closed Before Phase 0)

ENC-ISS-128 — Coordination dispatch creates phantom tasks (P1). The coordination dispatch currently creates coordination-only tasks instead of dispatching to existing governed tasks. This bug will corrupt tracker data during any extended migration period where agent coordination is active. Close before Phase 0 begins. No exceptions.

ENC-ISS-094 — Codex MCP missing checkout-service lifecycle tools (P1). Codex cannot participate in governed task execution without checkout-service tools in its MCP profile. Close or formally scope it to API key auth strategy before Phase 3.

### Soft Gates (Must Be Actively In-Progress Before Phase 2)

ENC-ISS-142 — Agent escalation protocol missing (P2). Agents must propose specific human actions when blocked. A `coordination.escalate` action or equivalent must be designed and deployed before Phase 2.

ENC-ISS-125 — Codex 401 Unauthorized (P1). The Codex auth failure should be resolved as part of the auth bifurcation work in Phase 3, but the hypothesis and approach must be validated before Phase 3 begins.

ENC-ISS-070 — Claude Connector token not visible on auth dashboard (P1). This visibility gap makes auth debugging harder. Should be resolved during Phase 3 auth hardening.

### Recommended Pre-Phase 0 Sweep

Resolve any orphan tasks in the tracker (no parent or feature lineage). Ensure all v4 migration tasks have valid plan parent bindings in ENC-PLN-006. Run `plan.objectives_status` on ENC-PLN-008 and confirm all objectives are closed before treating it as a dependency.

---

## VI. Risk Registry

The following risks have been identified through analysis of open issues, institutional lessons, live stack state, and the April 2026 competitive landscape.

### RISK-001: Auth Complexity Cascade — Severity: P0

Auth and session failures are the #1 cross-project failure class in Enceladus history (ENC-LSN-011). Auth bugs consistently involve 3+ interacting root causes (ENC-LSN-007). Two P1 auth issues are currently open. The v4 migration adds three new auth surfaces: a REST API Gateway endpoint for MCP streaming, a bifurcated API key authentication scheme, and new Lambda service boundaries each requiring their own auth context.

Mitigation: Auth bifurcation (Phase 3) must be sequenced as the first infrastructure change in that phase — before MCP server modularization begins. All new service-to-service calls between decomposed Lambda functions must use internal API key authentication from day one, not OAuth. Define and test the bifurcated auth matrix in a dry-run environment before production deployment. Add explicit auth health checks to session initialization that verify both the Cognito path and the API key path independently.

### RISK-002: Coordination Dispatch Data Integrity — Severity: P1

ENC-ISS-128 documents that the coordination dispatch creates coordination-only tasks instead of dispatching to existing governed tasks. This is a live P1 bug. Hard gate: ENC-ISS-128 must be closed before Phase 0 begins.

### RISK-003: Graph as Memory — Single Point of Failure — Severity: P1

The v4 architectural philosophy explicitly designates "the graph is the memory." Neo4j AuraDB Free has no SLA, no guaranteed uptime, and no automated backup. Mitigation: implement daily automated Neo4j backup to S3 via a scheduled Lambda. Rebuild time target: under 15 minutes for full corpus. This must be completed before Phase 1 adds the vector index.

### RISK-004: Phase Dependency Ordering — Severity: P2

Phase 1 extends the graph_sync Lambda to add embedding calls and new node type projections. A regression in graph_sync introduced during Phase 1 could silently cascade into Phase 2 and Phase 4. Mitigation: mandatory 48–72 hour stabilization window between Phase 1 completion and Phase 2 kickoff. Define explicit health gates covering graph node count (must match DynamoDB record count ±2%), embedding coverage (must exceed 95% of all records), and graph_sync Lambda error rate (must be below 0.1% for 24 consecutive hours).

### RISK-005: Context Node Feature Flag Graduation — Severity: P2

Both `ENABLE_CONTEXT_NODES` and `ENABLE_LESSON_PRIMITIVE` are feature flags. The v4 architecture treats context nodes and lessons as core infrastructure — not opt-in features. Mitigation: schedule explicit feature flag graduation as a Phase 5 deliverable.

### RISK-006: Agent Escalation Gap During Migration — Severity: P2

ENC-ISS-142 documents that agents lack a formal escalation protocol when blocked. During a 12-week migration with service decompositions, feature flag toggles, dual-write windows, and partial state migrations, agents will encounter more genuinely ambiguous states than at any point in the platform's history. Mitigation: soft gate; a `coordination.escalate` action must be deployed before Phase 2.

### RISK-007: Orphan Task and Lineage Debt — Severity: P2

The tracker has accumulated orphan tasks with no parent or feature lineage. During a migration that will create dozens of new tasks, the absence of lineage enforcement means migration work itself could become orphaned. Mitigation: pre-Phase 0 sweep; enforce a lineage policy going forward.

### RISK-008: Multi-Provider Framework Neutrality — Severity: P2

Every major AI lab now ships its own agent framework with divergent calling conventions, authentication models, and tool-use patterns. Mitigation: define a provider adapter interface in the coordination API that isolates framework-specific SDK calls behind a common contract. This is a Phase 3 architectural commitment.

### RISK-009: Regulatory Compliance Trajectory — Severity: P3

The EU AI Act sets requirements for high-risk AI systems. Enceladus's governance model is architecturally aligned with these requirements and demonstrating this alignment is a genuine differentiator for enterprise AI roles. Mitigation: Phase 5 should include a brief EU AI Act compliance self-assessment mapping Enceladus governance primitives to Act requirements.

### RISK-010: Extended Migration Window Communication — Severity: P3

The migration spans 12 weeks across 21 active projects. During Phase 2 and Phase 4, there will be brief windows of elevated risk affecting all projects. Mitigation: before Phase 2 begins, produce a one-page impact matrix for the three most active projects documenting which operations may be briefly impacted, what the fallback behavior is, and what the rollback procedure looks like.

### RISK-011 (Revision 3): Component Hallucination Before H-SCHEMA Ships — Severity: P1

Before H-SCHEMA lands (P1–P5 preconditions enforced server-side), agents proposing new components for the four new v4 Lambda services can do so without address verification, repo-dir existence checks, or overlap detection. A hallucinated or mis-specified component address or repo path will corrupt the registry and block the H-BACKFILL checkout gate. Mitigation: no component proposals for v4 services should be submitted until H-SCHEMA is in-flight. Agents dispatched on Phase 2 work must include an explicit pre-flight: confirm H-SCHEMA task status before attempting any `component.propose` call. This rule is agent-side only until P1–P5 are server-enforced.

---

## VII. Migration Roadmap: Six Phases with Hardened Phase Gates

The migration plan is structured as six phases across twelve weeks. Each phase has explicit entry criteria and exit criteria. Do not skip gate validation.

### Phase 0: Zero-Cost Performance Wins + Pre-Flight Closure (Week 1)

Entry criteria: ENC-ISS-128 closed. ENC-PLN-006 objectives_set validated. All v4 migration tasks have plan lineage. H-SCHEMA task is created in the tracker and checked out (may be in-flight, not required to be closed).

Work: enable ARM64 on all Lambda functions (configuration changes only, no code); enable SnapStart on all Python 3.12+ Lambda functions; add provisioned concurrency (1 instance, 512MB ARM64) to the MCP server Lambda ($1.50/month); add `ReportBatchItemFailures` to all SQS-triggered Lambda event source mappings; implement daily Neo4j backup to S3 (required before Phase 1 adds vector index); begin resolution of ENC-ISS-142 (agent escalation protocol design); sweep and resolve orphan tasks.

Exit criteria: all Lambda functions reporting ARM64 in console. MCP server cold starts eliminated in CloudWatch (0 cold start events over 24h monitoring window). Neo4j daily backup confirmed with test restore. Orphan task count at 0.

Expected impact: 20% cost reduction, 90% cold start reduction across fleet. No migration window required.

### Phase 1: Vector Embedding Pipeline + Graph Projection Expansion + H-SCHEMA (Weeks 2–3)

Entry criteria: Phase 0 exit criteria met. Neo4j backup confirmed.

Work: create HNSW vector index on Neo4j AuraDB Free; fix graph_sync Lambda to project plan and lesson node types (currently missing); extend graph_sync Lambda to call Bedrock Titan V2 on every record mutation, writing embedding to both Neo4j (vector property) and DynamoDB (binary attribute); run one-time batch embedding of all approximately 2,789 records ($0.03); update `get_compact_context` handler to use three-signal hybrid retrieval pipeline. Backwards-compatible throughout: vector scores augment existing scoring; zero weight if embedding absent.

H-SCHEMA is Phase 1-adjacent and must ship within this window. H-SCHEMA adds `component_address`, `component_repo_dir`, `component_address_class`, `component_class`, and `required_transition_type_rationale` to the component schema; revises `required_transition_type` to the v3 enum `{code, external_deploy, documentation}`; adds `external_deploy_evidence` and `documentation_evidence` sub-schemas; extends `component.propose` with preconditions P1–P5; extends checkout_service `_handle_advance` with preconditions P6–P7; emits the `no_code` and `data_only` deprecation Lesson; adds 12 new unit tests.

Design constraint (ENC-ISS-180): when creating typed relationship edges (rel# items), the target record node must be confirmed present in Neo4j before `create_relationship` is called. graph_sync's MERGE silently no-ops when the target node is absent — no error, no retry, no recovery signal. v4 Record Service must enforce a pre-flight target-node check before any edge creation, or implement a reconciliation queue for edges whose target was not yet projected at write time. Do not carry this failure mode into v4.

48–72 hour stabilization window after Phase 1 before Phase 2.

Exit criteria (Phase 2 entry gate): graph node count matches DynamoDB record count ±2%. Embedding coverage ≥95% of all records. graph_sync Lambda error rate <0.1% for 24 consecutive hours. At least one end-to-end hybrid retrieval query validated against known records. H-SCHEMA task closed (evidence accepted). ENC-FTR-096 design document (memory consolidation Lambda architecture) authored in the docstore before this gate stamps (see AC-11 in ENC-TSK-B62).

### Phase 2: tracker_mutation Decomposition + H-BACKFILL (Weeks 4–6)

Entry criteria: Phase 1 exit gate passed. ENC-ISS-142 (escalation protocol) deployed. Dual-write infrastructure pattern documented. H-SCHEMA closed. H-BACKFILL task checked out.

Work: extract Lifecycle Service first (cleanest boundary); extract Scoring Service (move constitutional scoring to SNS-triggered async Lambda, lesson records gain `scoring_status: pending` → `scored` state). Each extraction is a separate task in Enceladus's own tracker, following the full checkout → code → PR → deploy arc. Parallel validation: both old and new paths run simultaneously for at least 48 hours. Feature flags for each extraction are independent — one can be rolled back without affecting the other.

H-BACKFILL runs concurrently with the decomposition work. H-BACKFILL populates the five hardening fields on all existing active components; executes T2 file split for `03-api.yaml` and registers the three resulting components; executes T3 external manifest creation for Neo4j and other in-scope external dependencies; executes T4a umbrella-per-CFn-file registration; registers a single umbrella `comp-enceladus-mcp` for the T1 MCP duo with a known-debt note pointing to ENC-FTR-094; migrates all `transition_type=no_code` and `transition_type=data_only` active tasks to the v3 enum (including ENC-TSK-F18 and ENC-TSK-F19 which carry governance debt on this field); renames `comp-umbrella-no-code` to `comp-umbrella-governance-documentation`.

The checkout gate (AC[2] of ENC-FTR-076) cannot be enabled until H-BACKFILL is complete. Phase 2's exit gate therefore implicitly requires H-BACKFILL closure.

Exit criteria: Lifecycle Service handling 100% of status transition validations with zero fallback to inline path for 48 consecutive hours. Scoring Service handling 100% of lesson scoring with zero inline scoring for 24 consecutive hours. tracker_mutation blast radius confirmed reduced. H-BACKFILL task closed with evidence accepted. All prod components satisfy I1–I5 or carry a documented known-debt note.

### Phase 3: MCP Server Modularization + Streaming + Auth Bifurcation (Weeks 6–8)

Entry criteria: Phase 2 exit criteria met. ENC-ISS-125 hypothesis validated. Auth bifurcation matrix documented and reviewed.

Work: auth bifurcation first (implement API key authentication for agent clients, update MCP server auth middleware to accept both schemes, validate with Codex managed sessions before touching MCP server structure); decompose `server.py` into package structure `mcp_server/{__init__, tools/coordination, tools/execute, tools/context, tools/search}`; add REST API Gateway endpoint for MCP Streamable HTTP transport with `responseTransferMode: STREAM`; route MCP traffic to new streaming endpoint while keeping HTTP API v2 as fallback; implement provider adapter interface in coordination API.

Note: the MCP server modularization is distinct from the T1 shared-source refactor (ENC-FTR-094). Phase 3 modularizes the package structure of `server.py` into handler modules without splitting the file into per-Lambda entry points. That split is a gamma-first operation deferred to ENC-FTR-094. The Phase 3 modularization is safe because both Lambda functions continue to share the same package structure; the T1 invariant violation (I2/I3) persists until FTR-094 closes.

Exit criteria: Codex successfully authenticating via API key with no OAuth redirect. Claude.ai connectors successfully authenticating via Cognito OAuth. MCP streaming endpoint returning 500ms TTFB on test tool calls. ENC-ISS-125 and ENC-ISS-070 confirmed resolved.

### Phase 4: Data Layer Optimization + H-DRIFT (Weeks 8–10)

Entry criteria: Phase 3 exit criteria met. Dual-write pattern validated in Phase 2.

Work: extract relationships to dedicated `enceladus-relationships` DynamoDB table; dual-write during transition: Record Service writes to both tables; reads check new table first with fallback to old; once all reads migrated, stop writing to old table and clean up rel# items from devops-project-tracker; zero downtime throughout; evaluate and implement EventBridge Pipes to replace Lambda glue code; graduate ENABLE_CONTEXT_NODES and ENABLE_LESSON_PRIMITIVE feature flags to always-on (single deployment).

H-DRIFT ships in this window. H-DRIFT implements D1–D4 daily drift audits in `enceladus-governance-audit` Lambda (address resolvability, repo-dir existence, MECE closure, transition-type/address-class semantic plausibility), emits per-audit Lesson records on drift detection (non-blocking), and emits a daily audit report document.

Exit criteria: all relationship reads served from `enceladus-relationships`. Zero rel# SK reads from devops-project-tracker. Feature flags removed from Lambda environment variables. EventBridge Pipes deployed for at least one DynamoDB Streams → Lambda → EventBridge pattern. H-DRIFT task closed.

### Phase 5: Operational Hardening + Observability + ENC-FTR-096 (Weeks 10–12)

Entry criteria: Phase 4 exit criteria met. ENC-FTR-096 design document confirmed in docstore (AC-11 of ENC-TSK-B62).

Work: add CloudFront cache behaviors for read-heavy API GET endpoints (60–300s TTLs); implement in-Lambda caching for governance rules, project metadata, transition_type_matrix (module-level variables with TTL checks); review and consolidate SNS topics — eliminate single-subscriber topics; add minimum viable observability: enable AWS X-Ray tracing on all Lambda functions, create a CloudWatch dashboard covering Lambda error rates by service, Neo4j graph_sync lag, embedding coverage %, DynamoDB write throttle events, and MCP server cold starts; update CloudFormation templates to reflect all v4 architectural changes; run full governance dictionary sync to capture new entities (Record Service, Lifecycle Service, Scoring Service, provider adapter interface, external_deploy_evidence schema, documentation_evidence schema, v3 transition_type_enum); produce EU AI Act compliance self-assessment mapping Enceladus governance primitives to Act requirements; update JWO-TSK-023: update jreese.net/enceladus-showcase.html with v4 narrative; implement ENC-FTR-096 (Memory Consolidation Lambda): nightly EventBridge-triggered Lambda scans inter-session Handoff documents in the docstore, identifies patterns recurring across ≥2 waves (co-cited records, recurring error classes, repeated governance decisions), proposes Lesson candidates via `documents.put` with `document_subtype=lesson` and status=draft pending io review before promotion to a governed Lesson record — the human remains the approval gate at all times; see DOC-E2379D980FA2 §4.1 for the episodic→semantic consolidation rationale and ENC-FTR-096 for the full acceptance criteria.

Exit criteria: X-Ray traces available for all five services. CloudWatch dashboard showing green metrics across all five services for 48 consecutive hours. Governance dictionary version bumped. Showcase page updated. ENC-FTR-096 deployed and first nightly run logged; at least one Lesson candidate document proposed from Handoff review and available for io review.

### v5 Generation Backlog (ENC-FTR-095)

ENC-FTR-095 (Sheaf Laplacian Computation on Neo4j — H¹ Governance Inconsistency Detection) is a PLN-006 objective but targets the v5 generation. It is gated on ENC-FTR-088 (tracker.graph_laplacian) reaching production status and io explicit authorization. No implementation work begins during the v4 migration window. The feature is tracked in PLN-006 objectives_set as a forward obligation: any agent dispatched against PLN-006 must confirm ENC-FTR-095 scope (v5, not v4) before attempting implementation. See §VIII for architectural context.

---

## VIII. Architectural Philosophy for Enceladus v4

Enceladus v4 is guided by five principles.

**The extended mind IS the architecture.** The foundational commitment, per ENC-PLN-006 (revised 2026-04-04) and the Inception Principle (DOC-0CAD28643E2F), is that Enceladus is not infrastructure that agents use — it is constitutively part of io's cognitive process. The platform is the structure through which intent becomes outcome. Governance degradation — orphan tasks, stale Lessons, schema drift, hallucinated component addresses — is not a data quality problem. It is cognitive impairment of the extended mind. Every v4 architectural decision is evaluated against this axiom: does it make the extended cognitive system more intelligent, more reliable, and more capable of translating intent into outcome? Prior framing of "bounded autonomy architecture" and "human-on-the-loop" remains valid as market language; internally it is superseded by this. For the mathematical and philosophical grounding of this principle, see DOC-E2379D980FA2 (cross-domain synthesis spanning four millennia of mathematics, philosophy, and intelligence science) and DOC-73FF5950DA61 (formal journal treatment proving the Inception Principle generates precise architectural requirements via Wasserstein geometry and RG scaling).

**The graph is the memory.** AI agents have no persistent memory across sessions. Enceladus's knowledge graph — with typed relationships, context nodes, and vector embeddings — serves as institutional memory that compounds over time. v4 makes the hybrid retrieval pipeline (vector + graph + keyword) the crown jewel of context assembly. And because DynamoDB is the authoritative source from which Neo4j can always be rebuilt, the memory is durable.

The 𝔈/𝔇 ontology (Applied Entelechy / Acquired Dynamis, per DOC-C6584044BEEB) formalizes this with empirical grounding: 𝔈 is the compute-loaded, low-latency subgraph serving present intent, bounded by a scale-appropriate budget; 𝔇 is the retained corpus at unbounded scale, decaying in retrievability but never in retention (FSRS-6 T3 threshold governs 𝔇→𝔈 eligibility). Every agent session is a transition operator 𝔇→𝔈 conditioned on intent, effected by the Pathway kernel K_eff(·|ι) — an approximate Wasserstein transport plan with PPR cold start and shrinkage estimation (K_eff = (1−w(n))·K_prior(·|anchor) + w(n)·K_observed(·|ι), shrinkage parameter τ≈20, RG-stable under Kemeny-Snell coarse-graining with contractive flow 2.7× from session to wave scale, F16 / DOC-F8D8470CBF91). Empirical fixed-point budgets at 16TB corpus anchor (F11 / DOC-18D2337D7E1F): B_session=40.2MB (99% intent coverage), B_wave=241.8MB, B_project=1.6GB, B_corpus=800GB. Cognitive temperature schedule (logarithmic, F15 / DOC-1E5E505CB51A): β_session=8.0, β_wave=5.1, β_project=3.2, β_corpus=2.3 — outperforms power-law by 5×. Percolation margin m=p_current−p_c: current hot-tier fraction |H|/|V|≈0.20–0.35, p_c≈0.18±0.07 (F12 / DOC-41D810873099), margin positive but thin — comp-percolation-monitor (ENC-FTR-085) provides nightly authoritative measurement feeding the BHC five-level alert ladder.

**Serverless economics are a strategic moat.** Running 21 projects with graph search, MCP server, multi-provider coordination, and deployment pipelines at $30–40/month is 100–1000x cheaper than enterprise alternatives at equivalent capability. Every architectural decision preserves this cost profile. The v4 additions total approximately $1.50–5/month. The constraint breeds creativity — S3 as a cache, DynamoDB Streams as an event bus, Neo4j Free as a graph+vector store. These aren't compromises; they're advantages that enterprise platforms cannot replicate at their scale.

**Decompose along trust boundaries, not technology boundaries.** The right service boundaries in v4 are trust and responsibility boundaries: Record Service owns data integrity, Lifecycle Service owns state machine correctness, Scoring Service owns constitutional evaluation, Checkout Service owns token lifecycle, MCP Server owns context assembly. Each service can be independently tested, deployed, and reasoned about by both human and AI agents — which matters enormously for a platform where the agents are both users and builders. The same principle applies to the component registry: each component owns a MECE slice of the deploy-source space, and no two components share a physical realization or source authority. At the global knowledge-graph level, the five component invariants I1–I5 constitute the first production implementation of sheaf-cohomology-style global consistency — each local component definition (address + repo-dir injection pair) combining into a globally consistent partition, with deviations made countable and auditable by server-side preconditions. Full sheaf Laplacian computation on Neo4j — monitoring H¹ (cohomology degree 1) as a governance inconsistency signal that no local inspection can replicate — is the highest-value open architectural research question (Q1 in DOC-E2379D980FA2 §4.4), formally tracked as ENC-FTR-095 and targeted for the v5 generation (gated on ENC-FTR-088 in production).

**Every task produces a governed artifact.** The Artifact-Genesis Corollary (DOC-157A790F9E8B §2.4), formalized 2026-04-22: any agent action that claims to satisfy an acceptance criterion must leave a trace that a future session can inspect. A lifecycle advance without a trace is an unfalsifiable claim. Unfalsifiable claims are hallucination fossils. The v3 transition_type enum (`{code, external_deploy, documentation}`) mechanizes this corollary: every accepted transition_type produces a verifiable artifact — a repo commit for `code`, a structured external-system ID plus reproducible retrieval steps for `external_deploy`, a novel-or-fresh docstore document for `documentation`. The deprecated `no_code` path, which admitted artifact-less advances, is removed. This is not a constraint layered on top of governance; it IS the operating contract of the autonomous system.

**Memory consolidation is an explicit process.** Every successful natural memory system has a consolidation arc from episodic short-term storage to semantic long-term storage — biological systems execute this during sleep via hippocampal replay, converting episodic traces into durable cortical schemas. Enceladus has the structural analogs: inter-session Handoff documents are the hippocampal buffer (short-term, session-scoped, high fidelity), graduated Lessons are consolidated semantic memory (long-term, FSRS-6 stabilized), and governance amendments are deeply encoded procedural memory. What v4 still lacks is the consolidation process itself: a periodic Lambda that reviews recent Handoff documents, extracts recurring patterns across ≥2 waves (co-cited records, recurring error classes, repeated governance decisions), and proposes Lesson candidates with a human-approval gate before promotion. Without this process, institutional knowledge grows only through deliberate Lesson authoring and misses the latent patterns distributed across Handoff documents that no single session inspects in aggregate. Phase 5 delivers ENC-FTR-096 (Memory Consolidation Lambda). See DOC-E2379D980FA2 §4.1 for the full episodic→semantic consolidation rationale and ENC-FTR-096 for the full acceptance criteria.

---

*End of Document | Enceladus v4 Architecture Blueprint — Revision 5 | 2026-04-22*
*Revised from Revision 4 to wire in formal feature tracker IDs. Changes: ENC-FTR-095 and ENC-FTR-096 added to Related and throughout §VII/VIII; Phase 5 title updated to reference ENC-FTR-096 explicitly; new §VII subsection documenting ENC-FTR-095 as v5 generation backlog objective with scope constraint for dispatched agents; §VIII trust-boundary principle references ENC-FTR-095 by ID; §VIII fifth principle references ENC-FTR-096 by ID; Phase 5 entry criteria adds ENC-FTR-096 design doc precondition; ENC-FTR-096 was already a PLN-006 objective; ENC-FTR-095 added as new PLN-006 objective.*

---

## Revision 11 Addendum (2026-06-17): Graph-Signal Performance — Per-Query AGA Session Cost and the Pre-Materialized Projection Path

This addendum records an architectural follow-up surfaced while remediating the ENC-ISS-304 hybrid-retrieval investigation (plan ENC-PLN-046). It extends Section III (The Vector Embedding Layer / Data Layer Architecture), Section VI RISK-003 (Graph as Memory — Single Point of Failure), and Section VII Phase 1 (Graph Projection Expansion).

### Finding

The graph signal in three-signal hybrid retrieval is delivered by Personalized PageRank over a Neo4j Aura Graph Analytics (AGA) projection. The current implementation builds that projection per query: every anchored get_compact_context / tracker.graphsearch call issues gds.graph.project(... memory='2GB'), which provisions a fresh AGA compute session. AGA serializes and rate-limits session creation, so anchored queries are either slow (14s+), silently fall back to the Cypher connectivity-degree proxy (which is NOT true PPR), or exceed the synchronous read budget entirely. This is one root cause across the lineage:

- ENC-ISS-265 (closed) — PPR/graph signal unavailable; fixed the AGA Sessions API contract (memory param, nodeId resolution) via ENC-TSK-F20 / F35, restoring gds_pagerank intermittently.
- ENC-ISS-268 (open, P1) — residual per-query AGA session-creation cost and intermittency; the session-reuse refactor. ENC-ISS-271 is the sibling AGA session-reuse issue.
- ENC-ISS-311 (closed, via ENC-PLN-046 / ENC-TSK-G98) — the same cost manifesting as anchored-query timeouts at the MCP read layer.

### Interim mitigation (shipped)

ENC-PLN-046 / ENC-TSK-G98 (PR #484, prod 2026-06-17) bounds the graph signal with an 8-second wall-clock deadline. On timeout the signal degrades to graph_algorithm='timeout' and hybrid retrieval returns vector + keyword via Reciprocal Rank Fusion instead of hanging. This makes the endpoint responsive but does NOT make the graph signal performant — under the deadline, anchored PPR still does not return for most anchors.

### Architectural target (follow-up)

A durable fix must remove per-query AGA session creation from the synchronous read path. Two complementary options:

- Option A — AGA session reuse (ENC-ISS-268). Cache a single AGA session (gds.session.getOrCreate) at Lambda scope and pass sessionId= on every gds.graph.project, eliminating per-call provisioning. Lowest-effort; preserves the per-query projection model.
- Option B — Pre-materialized persistent projection (ENC-ISS-311 follow-up). Maintain a long-lived named graph projection refreshed out-of-band (by graph_sync on write, or a scheduled job), so hybrid queries run gds.pageRank.stream against a warm projection rather than building one per request. Highest payoff; aligns the hot-tier Applied-Entelechy subgraph with a standing compute object instead of a per-query rebuild, and restores true gds_pagerank within the synchronous read budget.

Option B is the architecturally preferred end state and is the natural Phase 2+ / v5 graph deliverable; Option A is a valid stepping stone. RISK-003 (Graph as Memory — SPOF) is unchanged either way: the graph remains a derived index with tracker.list / DynamoDB as the authoritative fallback, and hybrid retrieval already degrades gracefully when the graph signal is absent.

Tracked under: ENC-ISS-268 (open, durable fix), ENC-ISS-311 (mitigation shipped), ENC-TSK-B62 (Phase 1 graph-projection gate, closed), ENC-PLN-046 (interim mitigation).

### Rev 11 Addendum follow-up (2026-06-17): Option B is now tracked as ENC-FTR-101

The pre-materialized persistent projection (Option B above) is filed as ENC-FTR-101 (P2, infrastructure, status=planned) and added to ENC-PLN-006 objectives_set as a Phase 2+ graph deliverable. ENC-FTR-101 depends on ENC-ISS-268 (AGA session reuse, the foundation) and cross-links ENC-ISS-311 / ENC-ISS-265 and the graph features ENC-FTR-088 / ENC-FTR-095. The ENC-TSK-G98 8-second deadline remains the interim safety net until ENC-FTR-101 lands.

---

## Revision 12 Addendum (2026-06-21): Energy-Based / Attractor-Memory Synthesis — Hopfield Lineage Incorporation

This addendum incorporates the recommendations of DOC-D3EA86857600 (research synthesis on the modern Hopfield lineage, grounding paper arXiv:2601.07635v2). It sharpens — it does not supersede — the §VIII principles, and threads concrete obligations into §III (Vector Embedding Layer), §VI RISK-003, and the §VII phase gates. The thesis: the platform's memory, retrieval, consolidation, and consistency machinery are all instances of one mature object — energy descent toward attractors in an associative memory — and adopting that single vocabulary makes the 𝔈/𝔇 ontology measurable rather than merely evocative. Each item below names the existing objective that absorbs it; net-new scope is enumerated in the dissemination map and is filed as governed records through the coordination supervisor, not from this document.

### Incorporation 1 — The graph is an energy-based associative memory (sharpens §VIII "The graph is the memory")

Three-signal hybrid retrieval is, formally, one step of gradient descent on a joint retrieval energy E(x) = E_vector(x) + lambda_graph · E_PPR/Laplacian(x) + lambda_kw · E_keyword(x): the vector term is the modern-Hopfield retrieval energy (Ramsauer et al. 2020 proved softmax attention IS the one-step retrieval rule of a continuous-state Hopfield network), the graph term is the Laplacian/diffusion smoothing made explicit by Graph Hopfield Networks (2026), and the keyword term is a seed/prior. Reciprocal Rank Fusion is a practical approximation to descending this joint energy. HippoRAG / HippoRAG 2 (NeurIPS 2024 / ICML 2025) — knowledge graph as hippocampal index plus Personalized PageRank — are near-existence-proofs of the Enceladus retrieval design and supply a benchmark methodology (multi-hop recall@k on MuSiQue / 2Wiki / HotpotQA) for validating it. Obligation: the energy form and per-retrieval energy logging are folded into the Pathway Primitive telemetry (ENC-FTR-082) and the get_compact_context hybrid pipeline; the formalization itself is net-new scope (see dissemination map, new objective N1).

### Incorporation 2 — 𝔈 sizing is an attractor-capacity problem; the percolation margin is the alpha-load gauge (sharpens §VIII 𝔈/𝔇 and §VI)

The hot tier 𝔈 is a Dense Associative Memory. Its governing control variable is the load ratio alpha = (effective stored patterns) / (hot-tier dimension). The classical Hebbian retrieval ceiling alpha_c ≈ 0.138 (Amit-Gutfreund-Sompolinsky 1985) is the operational analog of the spin-glass transition: below it, recall is clean; above it, frustration produces an exponential number of spurious minima. Modern dense memories reach exponential capacity with large basins, so 𝔈 load can run high provided the spurious-attractor rate (Incorporation 3) stays low. The percolation margin m = p_current − p_c already monitored by comp-percolation-monitor (ENC-FTR-085, p_c ≈ 0.18, F12) is reinterpreted as the alpha-critical-region gauge: it is the same phase boundary in graph-connectivity coordinates. Obligation: ENC-FTR-085 gains an alpha computation and a critical-region alert tied to the BHC five-level ladder (ENC-FTR-083); the BHC's logarithmic beta-schedule is reframed as a cognitive-temperature schedule (Incorporation 4).

### Incorporation 3 — Hallucination is a spurious attractor; make it a measured signal (sharpens §VIII "Every task produces a governed artifact" and §VI)

The "hallucination fossil" language in the Artifact-Genesis principle now has a precise associative-memory referent: a spurious attractor is an interference minimum near the factual manifold that corresponds to no stored record. Define spurious-attractor rate = the fraction of agent sessions / retrievals that converge to states matching no stored graph node and no sanctioned combination of nodes. It is the leading indicator of capacity overload (alpha past the critical region) and of governance hallucination. Obligation: spurious-attractor rate is emitted as a wave-close metric under Wave-Close Drift Telemetry (ENC-FTR-087) and surfaced on the BHC alert ladder (ENC-FTR-083); the cross-cutting definition and instrumentation are net-new scope (new objective N2). Regime caveat: a spurious state is pathological for clean recall but is also the substrate of useful synthesis/generalization — the classification of any given off-manifold attractor as hallucination versus emergent insight is a governance judgment io makes explicitly, which is exactly the kind of call a governance-first platform exists to hold.

### Incorporation 4 — Cognitive temperature is the beta knob already in the plan (sharpens §VIII 𝔈/𝔇)

The BHC logarithmic beta-schedule (beta_session=8.0 → beta_corpus=2.3, F15) is the inverse-temperature / retrieval-sharpness knob of a modern Hopfield network. The Pathway kernel K_eff (ENC-FTR-082), which effects the 𝔇→𝔈 transition, should be explicitly annealed within a session: open hot (broad Wasserstein transport integrating diverse 𝔇 context for exploration), cool toward commit (sharpen onto a single low-energy intent attractor). Separately, because the corpus is highly correlated (related records, near-duplicate docs), naive Hebbian-style encoding induces crosstalk; correlation-aware (pseudoinverse-style) encodings are the standard remedy and are noted as a Phase 2 hot-path consideration (new task N4). Obligation: annealed-beta on K_eff lands as an AC enrichment on ENC-FTR-082; the correlation-aware encoding note attaches to the embedding/retrieval path.

### Incorporation 5 — Consolidation is basin-shaping; add Crick-Mitchison unlearning (sharpens §VIII "Memory consolidation is an explicit process")

The episodic→semantic arc (ENC-FTR-096) is, in energy terms, the merging of many narrow episodic point-attractors (Handoff documents) into broad semantic prototype basins (graduated Lessons) — trading specificity for robustness, which is exactly what enlarges basins and frees capacity. The lineage also supplies a complementary mechanism Enceladus does not yet have: Crick-Mitchison "unlearning" (reverse learning; Hopfield-Feinstein-Palmer 1983) — a periodic anti-Hebbian "dream pass" that dampens over-stable and spurious attractors in the hot subgraph, equalizing basins. This is a mechanism-grounded garbage collector for governance memory and a natural sibling to the consolidation Lambda. Obligation: the basin-shaping framing enriches ENC-FTR-096; the unlearning/dream-pass mechanism is net-new scope (new objective N3), explicitly gated behind the same io-approval invariant as ENC-FTR-096 — no automated dampening of governed memory without a human gate.

### Incorporation 6 — Sheaf H¹ is the frustration term of the governance spin glass (sharpens §VIII trust-boundary principle)

The energy framing closes a conceptual loop already present in the blueprint: the I1–I5 component invariants define the globally consistent (low-energy) section, and the sheaf Laplacian H¹ signal (ENC-FTR-095, v5, gated on ENC-FTR-088) is precisely the topological frustration term — the obstruction to a globally consistent section that no local inspection can detect. ENC-FTR-088 (tracker.graph_laplacian, CSR + Fiedler) is the computational substrate; the Dirichlet/graph-energy quadratic form it exposes is the same energy object used in retrieval (Incorporation 1). No new scope and no schedule change: this is a framing note that unifies the consistency-detection research line (ENC-FTR-088 → 095) with the retrieval and capacity lines under one energy vocabulary. v5 scope guard on ENC-FTR-095 is unchanged.

### Incorporation 7 — Inference-time energy descent as a compute-governance primitive (forward / v5 research)

Energy-Based Transformers (Gladstone et al. 2025) reframe inference as variable-step energy minimization — more descent steps for harder problems, best-of-N over candidate energies as self-verification. This is a candidate compute-governance primitive for the Pathway kernel: budget descent steps per session against intent difficulty, with the higher per-step FLOP cost (3.3–6.6x vs feed-forward) made explicit in the budget hierarchy (ENC-FTR-083). Filed as forward/v5 research (new objective N5); no v4 implementation. Gated behind the same discipline as ENC-FTR-095 — dispatched agents confirm scope before any implementation.

### Caveat banner (applies to all seven)

These are productive analogies, not proven identities. The attention/Hopfield equivalence is rigorous; "PPR = energy descent" and "hallucination = spurious attractor" are theoretically motivated but only partially formalized — HippoRAG itself does not frame PPR as energy minimization (that bridge is the Graph Hopfield Networks line). Exponential-capacity and basin guarantees assume uncorrelated patterns; the Enceladus corpus is highly correlated, so correlation-aware encodings are a precondition for the capacity claims to transfer. Treat 2025–2026 preprint figures as provisional. The platform adopts the vocabulary and the measurements; it does not adopt the strong claims unverified.

### Dissemination map (objective-level)

Absorbed by existing planned objectives (AC enrichment, applied by the coordination supervisor — not from this architect session): ENC-FTR-082 (annealed-beta K_eff + per-retrieval energy logging, Incorporations 1/4); ENC-FTR-083 (cognitive-temperature framing + spurious-attractor/alpha alert rungs, Incorporations 2/3/4); ENC-FTR-085 (alpha-load computation + critical-region alert, Incorporation 2); ENC-FTR-087 (spurious-attractor-rate wave-close metric, Incorporation 3); ENC-FTR-088 (Dirichlet/graph-energy framing note, Incorporation 6); ENC-FTR-095 (H¹-as-frustration framing note, v5 guard unchanged, Incorporation 6); ENC-FTR-096 (basin-shaping framing, Incorporation 5).

Net-new governed records to file (proposed to the coordination supervisor; not created from this document): N1 — Energy-Based Retrieval Formalization (define E(x), per-retrieval energy logging, benchmark RRF vs Graph-Hopfield reference on multi-hop recall@k; P2; gated on ENC-FTR-101 / ENC-ISS-268 so true PPR energy is available). N2 — Spurious-Attractor / Hallucination Telemetry (cross-cutting definition + emission + BHC wiring; P2; edges to 083/085/087). N3 — Crick-Mitchison Unlearning / Dream-Pass (anti-Hebbian basin equalization over 𝔈; P3; io-approval-gated sibling of ENC-FTR-096). N4 — Correlation-Aware (pseudoinverse-style) Encoding for near-duplicate corpus items (Phase 2 hot-path task; mitigates Hebbian crosstalk). N5 — Inference-Time Energy Descent for the Pathway kernel (EBT-style variable-step minimization; v5 research; budget-aware). All five carry the standard guards: OGTM compliance on any new edge types, the v5 scope guard where applicable, and the io-approval invariant on anything that mutates governed memory.

Source: DOC-D3EA86857600 (research synthesis), grounding arXiv:2601.07635v2. Incorporated 2026-06-21 by the architect; tracker dissemination routed to the coordination supervisor under DD-3 scope separation.



---

## Revision 13 Addendum (2026-06-21): Flow-Reinforced Transport and Stigmergic Exploration — Physarum Lineage Incorporation

This addendum incorporates the active-mechanical decision-making findings of Schick et al. (*Decision-Making in Light-Trapped Slime Molds Involves Active Mechanical Processes*, PRX Life 2026, DOI 10.1103/rv7g-d9kx) and the surrounding *Physarum polycephalum* computation lineage — Tero et al. current-reinforcement network optimization (Science 2010), Nakagaki maze-solving (Nature 2000), Murugan–Levin mechanosensory strain integration (Advanced Materials 2021), and Reid slime-trail externalized memory (2012–2013). It sharpens — does not supersede — the §VIII principles and continues the energy-vocabulary established in Revision 12. The thesis: a brainless, decentralized organism computes an approximate optimal-transport plan over a physical network by reinforcing edges proportional to realized flow, exploring broadly then committing under pressure, and writing an externalized refractory trace to avoid re-traversal. Each of these is a mechanism Enceladus's 𝔈/𝔇 machinery either already implies or measurably lacks. Net-new scope is enumerated in the dissemination map and is filed as governed records through the coordination supervisor, not from this document. The N-series below continues the Revision 12 N1–N5 numbering (N6–N8).

### Incorporation 1 — Current reinforcement IS the Pathway kernel's transport update; the graph projection should be flow-weighted, not only PPR-walked (sharpens §VIII "The graph is the memory")

Tero's current-reinforcement law — tube conductivity evolving as a function of realized flow, `dD_ij/dt = f(|Q_ij|) − D_ij`, with high-flow tubes thickening and idle tubes atrophying — is a physical optimal-transport solver and the direct biological analog of K_eff (the 𝔇→𝔈 transport plan, ENC-FTR-082). Enceladus currently scores the graph signal with Personalized PageRank: a static read (diffusion centrality) over a uniformly weighted projection. The Physarum lineage supplies the missing write: reinforce graph edge weights by realized successful-retrieval traffic — how often an edge actually participated in a 𝔇→𝔈 transport that satisfied an intent — and decay edges that never carry flow. This makes the pre-materialized persistent projection (ENC-FTR-101) flow-adaptive rather than uniform: the hot tier's standing compute object becomes a current-reinforced network that converges toward the corpus's actual usage geometry, exactly as the mold's tube network converges to optimal transport. Obligation: a flow-reinforcement weight on the ENC-FTR-101 projection, fed by per-retrieval participation logging already implied by ENC-FTR-082's energy logging; the reinforcement/decay law itself is net-new scope (new objective N6, gated on ENC-FTR-101 so a standing projection exists to weight).

### Incorporation 2 — Constraint-shape selects the commit mode; exploration is broad and cheap, commitment is singular and pressure-loaded (sharpens §VIII 𝔈/𝔇 and Revision 12 Incorporation 4)

Schick's central result: the mold does not take the shortest path out of a light trap. It sends exploration protrusions in all directions, withdraws most, and reorganizes its peristaltic wave until the contraction mode aligns with the trap's longest axis — the geometry that lets pressure build to maximize mass transport — then commits there. Two lessons sharpen the annealed-β K_eff from Revision 12: (a) the explore→commit arc is mechanism-confirmed — open hot with broad, cheap, withdrawable probes integrating diverse 𝔇 context; cool toward a single pressure-loaded commit; (b) the commit target is not the nearest or shortest-path attractor but the mode the intent-constraint geometry makes most transport-efficient. This is a direct caution against greedy shortest-path retrieval and naive RRF top-1: let the shape of the intent constraint select the transport mode, not raw proximity. Obligation: AC enrichment on ENC-FTR-082 (annealed-β commit is constraint-shape-selected, not distance-greedy); no net-new record.

### Incorporation 3 — The slime trail is externalized, overwritable, anti-redundant exploration memory; Enceladus has only positive-reinforcement memory (sharpens §VIII "Memory consolidation is an explicit process")

Reid showed the mold lays extracellular slime and avoids its own trail — an externalized spatial memory that biases foraging toward novelty — and that this trace is overwritable by salience (a plasmodium crosses its own slime to reach high-quality food). Enceladus's memory is almost entirely positive: graduated Lessons, co-citation edges, PPR centrality — "go where signal is strong." It has no negative or refractory trace saying "this region was already traversed without yield; don't re-explore unless new salience justifies it." This is the missing anti-redundancy primitive: a decaying "visited" trace on records and paths an agent session already traversed unproductively, biasing the next session's 𝔇→𝔈 toward unexplored corpus, and overwritable when a high-value intent crosses it. It is the natural sibling to the Crick-Mitchison dream-pass (Revision 12, N3): unlearning dampens over-stable internal attractors; the stigmergic trace dampens re-traversal of already-walked paths. Obligation: net-new scope (new objective N7), carrying the io-approval invariant since it shapes governed memory, with re-traversal rate emitted as a wave-close metric under ENC-FTR-087.

### Incorporation 4 — Mechanosensory relative valuation: prefer dispersed corroborating evidence over a single stacked spike (sharpens §VIII trust-boundary principle and Revision 12 Incorporation 3)

Murugan–Levin found the mold prefers three masses spread along the horizon over one stacked mass of equal weight — a Weber-law-like relative valuation responding to how much of the strain horizon the evidence occupies, not to raw magnitude. The retrieval analog: prefer an intent supported by multiple dispersed corroborating records or edges (broad strain footprint) over one very-high-score single record (stacked mass). A dispersion/corroboration term in RRF fusion is a structural hedge against single-source spurious attractors — the hallucination telemetry of Revision 12, N2 — because a lone off-manifold spike is precisely a stacked mass with no horizon. Obligation: framing enrichment on the hybrid pipeline (ENC-FTR-082) plus a small net-new dispersion-weighting record (N8); edges to N2.

### Incorporation 5 — Decentralized constraint satisfaction with no central controller (sharpens §VIII trust-boundary / sheaf principle; framing only)

The mold has no central controller: globally coherent, near-optimal configurations emerge from local peristaltic contractions over a shared cytoplasmic medium. This is the same shape as the sheaf principle — global consistency (low H¹) emerging from local component definitions (I1–I5) with no global inspector, over a shared graph and DynamoDB substrate. *Physarum* is a biological existence-proof that local rules plus a shared transport medium reach global coherence. No new scope, no schedule change, v5 guard on ENC-FTR-095 unchanged: this is a framing note unifying the decentralized-emergence intuition with the consistency-detection line (ENC-FTR-088 → 095).

### Caveat banner (applies to all five)

Productive analogies, not proven identities. Tero current-reinforcement → optimal transport is rigorous within the Physarum flow model; its transfer to graph-retrieval edge weights is a heuristic, not a theorem. The "longest axis" result is specific to peristaltic pressure mechanics and must not be imported literally as "prefer long retrieval paths" — the transferable claim is constraint-shape selects the efficient mode, not "longer is better." Slime-trail memory is lossy and overwritable by design; that is a feature for exploration but disqualifies it as a durable record store (DynamoDB remains authoritative). The platform adopts the mechanisms and the measurements; it does not adopt strong biological claims unverified.

### Dissemination map (objective-level)

Absorbed by existing planned objectives (AC enrichment, applied by the coordination supervisor — not from this architect session): ENC-FTR-082 (constraint-shape-selected annealed-β commit, Incorporation 2; dispersion-weighting hook, Incorporation 4); ENC-FTR-101 (flow-adaptive edge weights on the persistent projection — the substrate N6 requires, Incorporation 1); ENC-FTR-087 (re-traversal / exploration-redundancy rate as a wave-close metric, Incorporation 3); ENC-FTR-088 and ENC-FTR-095 (decentralized-emergence framing note, Incorporation 5, v5 guard unchanged); ENC-FTR-096 (stigmergic trace framed as exploration-memory sibling to consolidation, Incorporation 3).

Net-new governed records to file (proposed to the coordination supervisor; not created from this document): N6 — Flow-Reinforced Graph Projection (current-reinforcement edge weighting: reinforce by realized successful-retrieval traffic, decay idle edges; P2; gated on ENC-FTR-101; edges to ENC-FTR-082 and ENC-FTR-085). N7 — Stigmergic Exploration Trace (decaying, salience-overwritable anti-redundancy "visited" trace biasing 𝔇→𝔈 toward unexplored corpus; P3; io-approval-gated sibling of Revision-12 N3 and ENC-FTR-096; emits to ENC-FTR-087). N8 — Dispersion/Corroboration Weighting (Weber-law-style preference for dispersed corroborating evidence over single stacked spike; hedge against single-source spurious attractors; P3; edges to ENC-FTR-082 and Revision-12 N2). All three carry the standard guards: OGTM compliance on any new edge types, and the io-approval invariant on anything that mutates governed memory.

Source: Schick et al., PRX Life 2026 (DOI 10.1103/rv7g-d9kx), grounding lineage Tero 2010 / Nakagaki 2000 / Murugan–Levin 2021 / Reid 2012–2013. Incorporated 2026-06-21 by the architect; tracker and ENC-PLN-006 dissemination routed to the coordination supervisor under DD-3 scope separation.



---

## Revision 14 Addendum (2026-06-22): Graph-Signal Reconciliation — F36 Closed ENC-ISS-268 via Bolt-Pool Resilience, Not Session Reuse; ENC-FTR-101's Foundation Re-grounded on DOC-D4CB8048798B

This addendum reconciles the Revision 11 Addendum (and the Graph-Signal Restoration Wave handoff DOC-7E83A8C219F0) against what was actually implemented in ENC-TSK-F36. It is filed by the ENC-FTR-101 WU2 dispatched session after a ground-truth reconciliation pass over ENC-ISS-268, ENC-ISS-271, ENC-TSK-F36, and io's field guide DOC-D4CB8048798B. It sharpens — does not supersede — the Rev 11 architectural target: Option B (pre-materialized persistent projection) remains the preferred end state.

### Why this addendum exists

Rev 11 framed the durable fix as Option A (AGA session reuse, ENC-ISS-268) and Option B (pre-materialized persistent projection, ENC-FTR-101), with FTR-101 depending on ENC-ISS-268 as its foundation. Two facts diverged once F36 landed:

- ENC-ISS-268 was closed by ENC-TSK-F36 (PR #391, prod 2026-06-22) via Bolt-pool resilience — neo4j driver tuning (max_connection_lifetime=300 below the NAT 350s idle-kill, keep_alive) plus a verify_connectivity / rebuild gate. F36 deliberately did NOT implement AGA session reuse; the session-reuse sketch is marked SUPERSEDED in the ISS-268 technical_notes.
- AGA session reuse — the actual Option A — is tracked by ENC-ISS-271 (open, P1), not ENC-ISS-268. Its post-F36 gamma probes returned true gds_pagerank on all three anchors but at ~50s p95.

### The three-concern model (canonical going forward)

The graph-signal lineage (ENC-ISS-265 then 268 then 271 then 311) braids three distinct concerns. F36 closed the first two; only the third remains open:

- Correctness — true gds_pagerank vs the cypher_fallback connectivity-degree proxy. FIXED by F36: all three ENC-ISS-265 probe anchors return gds_pagerank.
- Liveness — the dead Bolt/Arrow pool hang after Lambda container freeze (NAT 350s idle-kill, OAuth 3600s expiry). FIXED by F36: Bolt-pool resilience, now live in graph_query_api (_ensure_live_driver / _rebuild_neo4j_driver).
- Latency — per-call gds.graph.project with memory:2GB provisions a fresh AGA session every request (~50s p95), exceeding both the ENC-ISS-271 sub-20s AC and the synchronous MCP read budget. STILL OPEN. The ENC-TSK-G98 8-second deadline only bounds it (degrades to graph_algorithm=timeout); it does not fix it.

### Re-grounded foundation for ENC-FTR-101 (Option B)

io's field guide DOC-D4CB8048798B (Neo4j GDS Sessions in AWS Lambda) is the canonical implementation contract for both Option A and Option B and should be cited by every future session touching backend/lambda/graph_query_api/lambda_function.py. Key invariants:

- An AGA GDS session is a server-side compute object with a 1-hour idle TTL and a 7-day hard cap, identified by a stable name, created idempotently via the graphdatascience Python client GdsSessions.get_or_create(session_name=...). TTL resets only on gds.graph.project / algorithm calls, not on verify_connectivity or run_cypher.
- A graph projection lives INSIDE a session. Therefore a standing projection (Option B) can exist only inside a standing named session (the Option A substrate). Option B is NOT a read-path-only change; it requires the named-session architecture underneath.
- Recommended shape (the field guide's deployment pattern, which is Option B's shape): warm the named session out-of-band from an EventBridge scheduled rule that also rebuilds the standing projection; request-path Lambdas call get_or_create only to reattach (cheap) and run gds.pageRank.stream against the warm projection.
- Concurrency invariant: concurrent gds.graph.project on the SAME graph name throws FlightRuntimeException (already a job running). Projection must be single-writer / out-of-band; the request path must never project. This is exactly why Option B (one out-of-band projector plus many read-only reattachers) is the safe end state.

### Corrected dependency edges

- ENC-FTR-101 (Option B) depends on the named-session substrate of DOC-D4CB8048798B, with F36 Bolt-pool resilience as a necessary base (it keeps the request-path driver live but does not address latency). It does NOT depend on an ENC-ISS-268 session-reuse deliverable, which was never built.
- ENC-ISS-271 (Option A, open) and ENC-FTR-101 (Option B) share that substrate. Open coordination decision: land Option A first as a lower-effort stepping stone (~sub-5s p95), or fold the named-session substrate directly into the FTR-101 implementation and close ISS-271 as superseded-by-FTR-101. The 2026-06-22 WU2 dispatch selected Option B implement plus PR plus probe.

### AC-5 / Rev 13 linkage (unchanged)

The standing projection's relationship-property slot flow_weight (initialized 1.0 per edge) remains the schema hook for ENC-FTR-108 (Flow-Reinforced Graph Projection, Rev 13). Recorded here only to note the slot must be created by the out-of-band projector inside the named session, alongside the existing per-type weight property, so ENC-FTR-108 can begin writing adaptive weights without a schema migration.



## Revision 15 Addendum (2026-06-23): Dream-Science Design Lens — Bounded Consolidation, Gist-Distillation, and the Confabulation Gate (DOC-7D8C252B4C57)

This addendum incorporates the design-relevant findings of DOC-7D8C252B4C57 (*Dream Science as a Design Lens for Enceladus v4*), which connects five strands of sleep and dream science to the v4 memory architecture. It sharpens — does not supersede — the §VIII principles and continues the energy-vocabulary of Revision 12 and the transport-vocabulary of Revision 13. The thesis is narrow and load-bearing: the offline reorganization Enceladus most wants its memory layer to do — consolidate, abstract, and forget the right things — is exactly what biological sleep does, and the dream-science literature supplies two non-decorative obligations the plan did not yet carry: a *dosage bound* on the Crick-Mitchison dream-pass already filed as Revision-12 N3 (ENC-FTR-106), and a *content policy* for the consolidation Lambda (ENC-FTR-096). Unlike Revisions 12 and 13, this addendum introduces **no net-new governed records**: every incorporation is an AC enrichment or framing note on an objective that already exists, applied by the coordination supervisor under DD-3 scope separation, not from this document.

Provenance note: the historical anchor is exact. In July 1983, *Nature* volume 304 published Crick & Mitchison's reverse-learning theory of dreaming (pp. 111–114) and Hopfield, Feinstein & Palmer's "'Unlearning' has a stabilizing effect in collective memories" (pp. 158–159) as cross-citing companion papers — the literal seed of the dream-pass Revision 12 already adopted from the Hopfield lineage (DOC-D3EA86857600). DOC-7D8C252B4C57 is the dream-side reading of that same lineage and is now edge-linked to the Blueprint, to DOC-D3EA86857600, and to the two synthesis documents that already absorbed it (DOC-E2379D980FA2 §Part III/§4.1/§Part V; DOC-73FF5950DA61 §6.3/§11.2).

### Incorporation 1 — The dream-pass is a *bounded regularizer*; bound its dosage and measure retention, not only suppression (sharpens Revision-12 Incorporation 5 / ENC-FTR-106)

Revision 12 adopted the Crick-Mitchison anti-Hebbian "dream-pass" (N3 / ENC-FTR-106) as a basin-equalizing garbage collector for over-stable and spurious attractors, gated behind the io-approval invariant. DOC-7D8C252B4C57 supplies the discipline that pass was missing. Agliari, Alemanno, Aquaro & Fachechi (*Neural Networks* 177:106389, 2024; arXiv:2308.01421) prove that the number of unlearning iterations is a *regularization hyperparameter* — formally tying "dreaming" to overfitting control. The consequence is concrete and asymmetric: too much unlearning erodes genuine memories (under-fitting — graduated Lessons stop retrieving), too little leaves spurious basins intact (over-fitting — hallucination attractors persist). A dream-pass is therefore never an open-ended prune; it is a dosed regularizer whose dose must be bounded and whose effect must be measured on *both* sides of the trade. Obligation (AC enrichment on ENC-FTR-106, no net-new record): (a) the unlearning iteration count is parameterized as an explicit regularization hyperparameter with a bounded upper limit, not an open-ended sweep; (b) every pass measures both spurious-attractor suppression (the existing intent) *and* graduated-Lesson retention, with a hard halt-and-reduce threshold — if a pass measurably degrades retrieval of io-approved (graduated) Lessons at any dosage, it halts and reduces iterations rather than proceeding. The io-approval gate is the outer control loop on this dosage decision (Incorporation 3). Edge: DOC-7D8C252B4C57 stamped on ENC-FTR-106 alongside the existing DOC-D3EA86857600 and Blueprint edges.

### Incorporation 2 — Consolidation distills gist, not episodes; decouple candidates from the source episode and prioritize friction (sharpens §VIII "Memory consolidation is an explicit process" / ENC-FTR-096)

The empirically strongest bridge in DOC-7D8C252B4C57 is the Stickgold et al. (*Science* 290:350–353, 2000) Tetris finding and its Alpine Racer II companion: the sleeping brain replays the abstracted *gist* — falling blocks, skiing motion — while discarding the episodic surround (the room, the chair, the keyboard), and does so even in amnesic patients with bilateral medial-temporal-lobe damage who cannot recall having performed the task. The amnesic dissociation is the key result: abstraction proceeds even without an intact episodic record. This is the warrant for two sharpenings of the consolidation Lambda (ENC-FTR-096), which today extracts recurring patterns but does not constrain their *form* or *source-coupling*. Obligation (AC enrichment on ENC-FTR-096, no net-new record): (a) Lesson candidates are framed as *abstracted, transferable gist* — the pattern, not a transcript fragment of any single Handoff — and explicitly designed to survive pruning of the source episode (the amnesic license: aggressive raw-episode forgetting paired with durable abstracted retention is the heart of the 𝔈/𝔇 ontology, not a compromise); (b) candidate extraction is prioritized from high-friction, high-self-correction waves — the "need-to-learn" replay trigger, since the Tetris brain reviewed most what it had least mastered, and the platform already studies agentic self-correction cycles. Edge: DOC-7D8C252B4C57 stamped on ENC-FTR-096 alongside the existing Blueprint and DOC-D3EA86857600 references.

### Incorporation 3 — Activation-synthesis names exactly why the io-approval gate is load-bearing, not removable (sharpens §VIII and the io-approval invariant)

Hobson and McCarley's activation-synthesis hypothesis (1977) — the forebrain synthesizing coherent narrative from essentially random brainstem activation — is, read as engineering, a precise description of confabulation: a synthesis stage that imposes coherence on noise whether or not the underlying signal is real. This is the §VIII / Revision-12 spurious-attractor risk stated at the cognitive level, and it supplies the principled, non-negotiable justification for the io-approval gate on both ENC-FTR-096 (consolidation) and ENC-FTR-106 (dream-pass). The gate is not optimization debt to be engineered away by a future efficiency pass: any synthesizer manufactures coherence, so the synthesis step (Lesson drafting, candidate proposal, basin dampening) must never self-validate. Obligation (framing note, no scope change): the io-approval invariant on ENC-FTR-096 and ENC-FTR-106 carries the activation-synthesis rationale explicitly, so the gate's necessity is recorded on the records themselves and survives future refactor pressure. This is the deliberate disanalogy with biology — biological consolidation is autonomous and ungated; Enceladus inserts the human gate precisely because the dream machinery reliably fabricates coherence.

### Incorporation 4 — Selective replay (~10–30%) is the biological license for the budget hierarchy's aggressive selectivity (sharpens §VIII 𝔈/𝔇 and Revision-12 Incorporation 2)

Hippocampal replay (Wilson & McNaughton, *Science* 265:676–679, 1994) is selective: across methods, only ~10–30% of sharp-wave ripples carry significant memory reactivation. The brain does not replay everything; it replays a salience-weighted minority, and consolidation works *because* of that selectivity. This is the natural-system sanity check on the F11 budget hierarchy: a session-scale 𝔈 that materializes well under 1% of 𝔇 (B_session = 40.2 MB, k*_session = 1.005 × 10⁴ against a 2 × 10⁸-node corpus, 99% intent coverage) is operating in the same selective regime as a biological memory system — not a compute-forced compromise. Obligation (framing note on the BHC / ENC-FTR-083 and §VIII 𝔈/𝔇, no scope change): the percolation-monitored hot-tier sizing is read as biologically licensed selective transport; the empirical replay fraction is the cross-check that the session-budget targets are reasonable, reinforcing Revision-12 Incorporation 2's alpha-load framing from the replay side.

### Incorporation 5 — Offline rehearsal ↔ dry-runs and simulation batches (framing only; the most contested strand)

Revonsuo's Threat- and Social-Simulation theories frame dreaming as offline rehearsal of waking challenges in a consequence-free arena — the analog of Enceladus's dispatch dry-runs (`dispatch_plan.dry_run`, governed `execute` with `dry_run=true`) and simulation batches. The mapping is heuristic and the science is the most contested of the five strands (Domhoff and others deny any adaptive function), so this is framing only, with no net-new scope: the platform already treats its simulations as engineering validation with quantitative outcomes (collapse / convergence / win-rate) rather than assuming offline rehearsal confers benefit, which is exactly the discipline the contested status demands. No objective changes; recorded here so the analogy is governed rather than informal.

### Caveat banner (applies to all five)

Standing varies sharply across the five strands, and the addendum imports only what the evidence supports. Hippocampal replay and systems consolidation (Incorporation 4) are well-established and mechanistic. Activation-synthesis (Incorporation 3) is substantially revised but not refuted, and is used only to name a failure mode. Consolidation-views of dreaming (Incorporation 2) are supported but largely correlational — the gist-abstraction *finding* is robust and replicated, while the claim that the dream itself does the consolidating remains open; the design borrows the content policy, not the causal claim. Crick-Mitchison reverse learning (Incorporation 1) is marginalized as dream neuroscience even as it is vindicated as computational mathematics — the Agliari-2024 regularization result is the rigorous part, and it is the only part the dosage bound depends on. The simulation theories (Incorporation 5) are the most contested and are imported as framing only. The two load-bearing additions — the dosage bound on the dream-pass and the gist/episode-decoupled content policy on consolidation — both sit behind the io-approval gate, so even where the science is provisional the human control loop absorbs the risk. The platform adopts the mechanisms and the measurements; it does not adopt strong biological claims unverified.

### Dissemination map (objective-level)

Absorbed by existing planned objectives (AC enrichment / framing note, applied by the coordination supervisor — not from this architect session): ENC-FTR-106 (bounded-regularizer dosage AC + dual-measurement spurious-suppression-and-Lesson-retention AC with halt-and-reduce threshold + Crick-Mitchison↔Hopfield 1983 lineage provenance + DOC-7D8C252B4C57 edge, Incorporation 1); ENC-FTR-096 (gist-abstraction-and-episode-decoupling AC + high-friction/self-correction prioritization AC + activation-synthesis gate-rationale framing on the io-approval invariant + DOC-7D8C252B4C57 edge, Incorporations 2/3); ENC-FTR-083 (selective-replay budget-selectivity framing note, Incorporation 4); ENC-PLN-006 (intent enrichment: dream-science design lens added as the natural-system research substrate for the consolidation/dream-pass cluster, with DOC-7D8C252B4C57 as a related edge, Incorporations 1–3).

Net-new governed records to file: **none.** DOC-7D8C252B4C57 sharpens objectives that already exist (the dream-pass N3 / ENC-FTR-106 from Revision 12, and the consolidation Lambda ENC-FTR-096); it adds discipline and content policy, not a new mechanism. This is the deliberate, juice-positive read: the strongest contribution of the dream-science lens is to *bound* and *constrain* work already planned, which lowers risk rather than adding surface area. The simulation-as-rehearsal analogy (Incorporation 5) is framing only and files no record.

Source: DOC-7D8C252B4C57 (*Dream Science as a Design Lens for Enceladus v4*), grounding Crick & Mitchison 1983 / Hopfield-Feinstein-Palmer 1983 (*Nature* 304) / Agliari et al. 2024 (*Neural Networks* 177:106389) / Stickgold et al. 2000 (*Science* 290) / Wilson & McNaughton 1994 (*Science* 265). Incorporated 2026-06-23 by the architect; tracker and ENC-PLN-006 dissemination routed to the coordination supervisor under DD-3 scope separation. The two synthesis documents (DOC-E2379D980FA2, DOC-73FF5950DA61) had already absorbed this lens in their 2026-06-23 refactors; this addendum closes the remaining gap by carrying it into the operational Blueprint.



## DEPLOY TARGET INVARIANT — v4 Work is Gamma-Only (established 2026-06-23)

**Invariant:** All implementation work under ENC-PLN-006 deploys exclusively to the gamma environment. The v3-prod environment is frozen for the duration of this plan.

**Operative contract (as of 2026-06-23):**

- `v4/main` is the sole active development branch for all PLN-006 work.
- Every push to `v4/main` triggers the v4-gamma deploy via `_deploy.yml`. This is the intended and only authorized deploy target for in-flight v4 work.
- `promote-gamma-to-prod-request.yml` fires on gamma success but the resulting v3-prod deploy request will NOT be approved by io until ENC-PLN-006 reaches full E2E validation on gamma. Agents must not assume, request, or anticipate prod promotion.
- `sync-main-to-v4main.yml` is DISABLED (ENC-TSK-H63). v3 main changes do not flow into v4/main. Any agent that re-enables this workflow or attempts to merge main into v4/main is in violation of this invariant and must halt and surface to io.
- Direct CLI CloudFormation deploys to the prod stack are prohibited per DOC-733D76F4849B and the LSN-039 pre-probe rule.

**For dispatched agents:** When your task touches Lambda code, infrastructure, or any deployable artifact, your deploy target is gamma. Use the canonical gamma deploy scripts per DOC-733D76F4849B. Do not touch the prod stack. If your checkout transition produces a deploy artifact that targets v3-prod, STOP and surface to the coordination lead before proceeding.

**Cutover trigger:** io will explicitly approve a v3-prod promote request when PLN-006 gamma validation is complete. That approval is the only valid prod promotion signal. No agent session initiates or requests prod promotion.



### main → v4/main auto-sync DISABLED (ENC-TSK-H63 — 2026-06-23)

`sync-main-to-v4main.yml` — which fast-forwarded / `-s ours`-absorbed every `main`
push into `v4/main` during pre-fork mirroring — is **disabled for the duration of
ENC-PLN-006** via a job-level `if: ${{ false }}` guard (PR #536, merge commit
`b576ac2`, merged 2026-06-23T16:15:13Z).

- **Why:** `v4/main` has diverged ahead of `main`; continued auto-sync is a collision
  risk (`-s ours` clobber of v4/main's tree, or fail-loud on every main push).
- **Still active:** `promote-gamma-to-prod-request.yml` — the v3-prod Environment
  approval gate remains the cutover toggle (ENC-TSK-G71).
- **Re-enable rule:** do **not** remove the `if: ${{ false }}` guard without io
  approval; re-enable only at the v4 → main cutover.
- **Verified:** the disable-merge push to `main` ran the sync job **skipped** (run
  28039982782); the gamma→promote chain stayed green on v4/main pushes
  (28010334072 → 28010513422).



## Revision 16 Addendum (2026-06-23): Universal Arc-Walker (ENC-FTR-111) — Mechanical-Gate Forward Automation in the Lifecycle Service

This addendum aligns the Blueprint with the Universal Arc-Walker feature (ENC-FTR-111, design DOC-078C57FC1BE6), materialized as an ENC-PLN-006 objective and a seven-task tree (ENC-TSK-H82 through ENC-TSK-H88) per DOC-607DF1D4B595. It is an additive alignment — no §III/§VII/§VIII text is rewritten — recording how the new feature is reflected in three existing sections:

- **§III Service Boundary Decomposition (Lifecycle Service).** The Lifecycle Service additionally hosts the Universal Arc-Walker (ENC-FTR-111, DOC-078C57FC1BE6): a forward-derivation capability over the same transition_type_matrix that auto-advances records across mechanical gates while the attestation floor keeps attestation and io-gated transitions structurally unreachable by automation.
- **§VII Migration Roadmap (Phase 2 work).** Arc-walker (ENC-FTR-111) is a follow-on to the Lifecycle Service extraction (ENC-TSK-H46), sequenced after it reaches deploy-success; Phase 1 ships the opt-out latch and the inline mechanical walk.
- **§VIII Architectural Philosophy (Decompose along trust boundaries).** Lifecycle correctness includes safe forward automation: the arc-walker automates mechanical progression and treats every attestation and io-gated transition as non-walkable by type, making the io-approval invariant structural rather than procedural.

This addendum introduces no net-new governed records of its own; the feature and its seven tasks are governed under ENC-FTR-111 / ENC-PLN-006. Gate eligibility in the walker is decided by an explicit per-cell gate_class (mechanical / external-fact / attestation), not by evidence-field emptiness.




## Revision 17 Addendum (2026-06-28): Production-Cutover Readiness + RISK-001–011 Confirmation (ENC-TSK-B69)

Filed by the ENC-TSK-B69 dispatched governed gamma session (governance_hash 584baae9…). This addendum records the **production architecture state as of 2026-06-28** for the ENC-PLN-006 “Production Cutover + Showcase Live” objective and formally confirms each Risk Registry entry (§VI) as mitigated or accepted-residual. It is additive — no §I–§VIII text is rewritten.

### Current production architecture state (honest snapshot)

The production cutover named by ENC-TSK-B69 has **not** occurred and is **not** an agent-actionable step. The governed truth:

- **v3 (ENC-GEN-001) is the live production baseline and is frozen** for the duration of ENC-PLN-006 (DEPLOY TARGET INVARIANT, 2026-06-23). No v3 Lambda stack is decommissioned; the decommission criterion cannot be satisfied while v3 is the serving generation.
- **v4 (ENC-GEN-002) runs on the durable gamma stack** — its own control, data, and graph planes. Per the io durability decision (DOC-A07B553431FD, reconciled via ENC-TSK-H59), gamma is a permanent pre-production environment and is **not** torn down at cutover; the gamma-teardown criterion is formally retired (already evidence-accepted on B69).
- **The cutover is a single io-approved promotion gate** (`promote-gamma-to-prod-request.yml`, ENC-TSK-G71). No agent session initiates, requests, or derives prod promotion. `sync-main-to-v4main.yml` remains disabled (ENC-TSK-H63).
- **ENC-PLN-006 is at ~19% objective closure** (7/36 closed; Phase 2–5 gates ENC-TSK-B63/B64/B65/B66 and the cockpit/HCE objectives still open). Production-cutover readiness is therefore **partial**: Phase 0/1 and the Gamma-Operational gate (ENC-TSK-B60) are closed; the remaining phase gates must pass gamma validation before io’s promotion gate is reached.

Net assessment: **B69 is a capstone objective correctly blocked on the rest of PLN-006 plus an io decision.** Its documentation/knowledge artifacts (showcase v4 narrative, this architecture-state confirmation, the risk confirmation below, and ≥5 captured lessons) are deliverable now; the infrastructure cutover and v3 decommission are not and must not be asserted complete.

### RISK-001 – RISK-011 confirmation (§VI Risk Registry)

- **RISK-001 Auth Complexity Cascade (P0) — MITIGATED.** Auth bifurcation shipped (API-key for agents, Cognito OAuth for interactive); `connection_health.auth_config` reports all five internal API-key paths configured; ENC-LSN-011 / ENC-LSN-007 institutionalized. Residual: monitored, not eliminated.
- **RISK-002 Coordination Dispatch Data Integrity (P1) — MITIGATED.** Hard gate ENC-ISS-128 is **closed** by ENC-TSK-B71 (PR #220).
- **RISK-003 Graph as Memory — SPOF (P1) — MITIGATED (residual accepted).** Daily Neo4j→S3 backup (ENC-TSK-B85); DynamoDB authoritative rebuild source; hybrid retrieval degrades gracefully. Graph-signal latency tracked separately (ENC-ISS-271 / ENC-FTR-101, G98 deadline). Residual: AuraDB Free has no SLA — accepted with rebuild path.
- **RISK-004 Phase Dependency Ordering (P2) — MITIGATED.** Phase gates carry explicit entry/exit health gates and 48–72h stabilization windows (§VII).
- **RISK-005 Context-Node / Lesson Flag Graduation (P2) — MITIGATED (in progress).** Scoped as Phase 4 / AppConfig work (ENC-FTR-103); flags resolve via the AppConfig platform. Residual until Phase 4 closes.
- **RISK-006 Agent Escalation Gap (P2) — MITIGATED.** ENC-ISS-142 is **closed** (ENC-TSK-H48–H53; escalation-trail convention DOC-CA807143B16A).
- **RISK-007 Orphan Task / Lineage Debt (P2) — ACCEPTED RESIDUAL (managed).** Pre-flight sweep done; lineage enforced via plan objectives_set + PLAN_CONTAINS projection; ongoing hygiene via drift audits.
- **RISK-008 Multi-Provider Framework Neutrality (P2) — MITIGATED.** Provider-adapter surface + server-minted agent/session identity (ENC-FTR-117 / ENC-TSK-I38).
- **RISK-009 Regulatory Compliance Trajectory (P3) — ACCEPTED RESIDUAL.** EU AI Act self-assessment remains Phase 5 (ENC-TSK-B66); governance substrate already aligns architecturally.
- **RISK-010 Extended Migration Window Communication (P3) — ACCEPTED RESIDUAL.** The durable-gamma posture removes the big-bang cutover-window framing: v4 matures continuously on gamma and promotion is a single gated switch. Accepted as residual; impact-matrix practice retained.
- **RISK-011 Component Hallucination Before H-SCHEMA (P1) — MITIGATED.** Five-surface required_transition_type enforcement (ENC-TSK-F50 / ENC-ISS-270) + OGTM gate (ENC-FTR-066) make hallucinated component addresses server-rejectable.

**Conclusion:** RISK-001–011 are each mitigated or accepted-residual. No open risk blocks the gamma-validation track; the only remaining cutover dependency is completion of the PLN-006 phase gates plus io’s explicit promotion approval.

*Filed 2026-06-28 by the ENC-TSK-B69 governed gamma session. governance_hash 584baae9044510d86bbd331d844529d357b7aacff5c5c127c696f8cf94dde0f1. This addendum asserts no completed production cutover; the v3 decommission and the live showcase publish (JWO-TSK-023) remain io-gated.*


## Revision 18 Addendum (2026-07-02): v3 Feature Carryover Ledger + Unplanned Feature Absorption (Ground-Truth Sweep)

Filed by an io-directed webui-alpha governed session against live tracker state (governance_hash 7c4e44e8…). Two purposes: (a) record every feature shipped and live in v3 that persists into v4 — the carryover inventory the greenfield rebuild absorbs; (b) formally absorb into blueprint scope the five unplanned features that landed mid-migration. Additive — no §I–§VIII text is rewritten. Per-feature gamma E2E parity is asserted only where validated; the J79 gamma sweep (DOC-45D8B5FB6FD6: 14/17 backend actions PASS, PWA smoke PASS) plus the B59 absorption objective are the parity evidence surfaces, and ENC-TSK-K11 tracks the three failing actions.

### Unplanned feature absorption (mid-migration drop-ins)

Five features entered scope after Revision 17 without prior blueprint provenance. They are now first-class v4 scope:

```yaml
unplanned_absorbed:
  - id: ENC-FTR-117
    title: Agent ID v3 — governed session and agent-type identity
    status: production
    blueprint_effect: strengthens RISK-008 mitigation; SCI precondition
  - id: ENC-FTR-118
    title: Autonomous Dispatch Engine (ADE)
    status: completed
    blueprint_effect: changes PLN-006 execution model — catalog-driven autonomous dispatch (DOC-841F5D649EEF) replaces manual wave dispatch
  - id: ENC-FTR-119
    title: Session-stall watchdog + enceladus-support satellite repo
    status: planned (J48 -> J49 -> J50 chain)
    blueprint_effect: introduces an isolated helper deploy lane OUTSIDE the v4 service map by design; zero write path to governed surfaces
  - id: ENC-FTR-121
    title: Escalations — human-gated mutation override surface
    status: completed (Ph6 validation ENC-TSK-J73 open)
    blueprint_effect: productizes the io-approval invariant (§VIII) as a first-class primitive; deploy-arc immutability gate gains an approved override path
  - id: ENC-FTR-122
    title: Session Claim ID (SCI) enforcement + retirement lifecycle
    status: planned
    blueprint_effect: closes ENC-ISS-441; converts the FTR-117 register->claim handshake from advisory to enforced (403 fail-closed)
```

Scope posture: FTR-117/118/121 are absorbed as shipped; FTR-119/122 are absorbed as committed near-term scope. None alter the six-phase gate structure (§VII); FTR-122 attaches to Phase 5 hardening, FTR-119 sits outside all phases by isolation design.

### v3-production carryover ledger (35 features)

Every feature below is status=production on the live tracker as of this sweep — the v3 serving surface v4 must reach parity with before io's promotion gate. Gamma parity notation: `validated` (explicit gamma evidence exists), `absorbed` (carried by the v4 greenfield rebuild + J79 sweep coverage), `at-risk` (a known gamma defect touches it).

```yaml
v3_production_carryover:
  governance_core:
    - {id: ENC-FTR-011, title: Product ontology governance, gamma: absorbed}
    - {id: ENC-FTR-012, title: Ontology schema enhancement, gamma: absorbed}
    - {id: ENC-FTR-022, title: Disciplined deployment lifecycle state governance, gamma: absorbed}
    - {id: ENC-FTR-026, title: Governance data dictionary (HTTP + DDB), gamma: validated}
    - {id: ENC-FTR-030, title: Server-authoritative datetime, gamma: absorbed}
    - {id: ENC-FTR-035, title: Enhanced lifecycle stage gates, gamma: validated}
    - {id: ENC-FTR-037, title: Abstracted checkout service, gamma: validated}
    - {id: ENC-FTR-041, title: Structured component registry, gamma: absorbed}
    - {id: ENC-FTR-043, title: Session lifecycle primer, gamma: absorbed}
    - {id: ENC-FTR-117, title: Agent ID v3 session identity, gamma: validated}
  knowledge_primitives:
    - {id: ENC-FTR-049, title: Typed relationship edge primitive, gamma: absorbed}
    - {id: ENC-FTR-050, title: Context node primitive, gamma: absorbed}
    - {id: ENC-FTR-052, title: Lesson primitive + constitutional scoring, gamma: validated}
    - {id: ENC-FTR-053, title: Cross-project knowledge mining, gamma: absorbed}
    - {id: ENC-FTR-054, title: Server-side constitutional scoring, gamma: validated}
    - {id: ENC-FTR-061, title: Handoff primitive, gamma: absorbed}
    - {id: ENC-FTR-088, title: tracker.graph_laplacian read action, gamma: at-risk}
    - {id: ENC-FTR-110, title: Dispersion/corroboration RRF weighting, gamma: absorbed}
  retrieval_and_graph:
    - {id: ENC-FTR-085, title: Percolation monitor nightly, gamma: validated}
  mcp_surface:
    - {id: ENC-FTR-016, title: Desktop MCP session briefing set, gamma: absorbed}
    - {id: ENC-FTR-033, title: Universal cross-project changelog, gamma: absorbed}
    - {id: ENC-FTR-044, title: Code-mode MCP four-tool SDK surface, gamma: validated}
  pwa_v1_surface:
    - {id: ENC-FTR-002, title: Manual refresh link, gamma: superseded-by-B67}
    - {id: ENC-FTR-008, title: Rich markdown rendering, gamma: superseded-by-B67}
    - {id: ENC-FTR-009, title: Parent/child hierarchy + RelatedItems, gamma: superseded-by-B67}
    - {id: ENC-FTR-010, title: Project reference route, gamma: superseded-by-B67}
    - {id: ENC-FTR-017, title: UI 1.0 philosophy launch schema, gamma: superseded-by-B67}
    - {id: ENC-FTR-036, title: Dynamic project card status/ordering, gamma: superseded-by-B67}
    - {id: ENC-FTR-038, title: Copy button for IDs/code, gamma: superseded-by-B67}
    - {id: ENC-FTR-039, title: Dynamic homepage project cards, gamma: superseded-by-B67}
    - {id: ENC-FTR-051, title: On-demand markdown download, gamma: superseded-by-B67}
    - {id: ENC-FTR-073, title: Detail page direct API fallback, gamma: superseded-by-B67}
  devops_and_ops:
    - {id: ENC-FTR-029, title: EC2 Codex session archive to S3, gamma: absorbed}
    - {id: ENC-FTR-040, title: Plan-mode auto documentation, gamma: absorbed}
    - {id: ENC-FTR-102, title: Env-parity gate for CFN compute deploys, gamma: validated}
```

The pwa_v1_surface cohort persists in v3-prod until cutover but is NOT ported file-for-file: ENC-TSK-B67 (PWA 2.0 Governance Cockpit, 24 ACs, spec DOC-E470AC8CE9A8) is the successor surface and must re-deliver each capability natively (its AC-20/21/22 already bind the ISS-121/137/138/139 re-deliveries). ENC-FTR-088 is at-risk pending ENC-TSK-K11 (embeddings/sheaf handler fix, ISS-474 adjacency).

### Completed-cohort features (21) — absorption note

Features at status=completed (post-v3-freeze era, gamma-first under DOC-499FA089EC30) are v4-native scope, not v3 carryover; the tracker is their authoritative registry. Notables wired into blueprint sections: ENC-FTR-099 (token economics, §IV heavier), ENC-FTR-101 (pre-materialized projection, Rev 11/14 — superseded operationally by the ISS-465 GDS cost-kill invariant), ENC-FTR-097 (manifest primitive), ENC-FTR-118/120/121 (above).

*Filed 2026-07-02 by an io-directed governed webui-alpha session. governance_hash 7c4e44e81e181d62edb5297d46707bd2390da99ee8584142fa40b5595d1ce241. Ledger derives from live tracker.list/tracker.get reads this session; no feature status asserted beyond tracker ground truth.*



## Search Stack (Multi-Project Cockpit) — Summary + Reference

**Full design: DOC-77D6C714867E** (Search + Sync Middleware — Multi-Project Cockpit Architecture). Added here as a §VII/PWA-adjacent capability summary; PLN-006 Phase-7 objective ENC-TSK-B67.

Enceladus v4 is THE multi-project governance cockpit: every record in ANY project must be retrievable AND visible in the PWA in <500ms p95 with best-in-class search. The stack is a hybrid over an adaptive tiered client cache + a server-authoritative corpus:

- **Semantic / vector tier (LIVE on gamma):** `graph_query_api` `GET /api/v1/tracker/graphsearch` — Titan Text V2 256-dim HNSW + PageRank + keyword, fused by RRF (k=60); fed by `graph_sync` (DDB Streams → EventBridge Pipe → SQS FIFO → Neo4j AuraDB).
- **Keyword / facet tail tier (LOCKED — self-hosted OpenSearch, io 2026-07-05):** a single **`t4g.small` graviton** OpenSearch node (Apache-2.0 fork of Elasticsearch), **~$8–13/mo** (0-replica, single-AZ, public-subnet + locked SG, **no NAT**, **not** OpenSearch Serverless). Fed **additively** by a new indexer consumer on the SAME `graph_sync` CDC spine — no rebuild. `graph_query_api`'s keyword arm swaps to OpenSearch (fuzzy/typo, BM25 relevance, faceted counts, autocomplete) with a Neo4j full-text circuit-breaker fallback; the client still calls the single `/graphsearch` endpoint. Rejected alternative: DynamoDB prefix GSI (instant but prefix-only — no fuzzy/relevance/facets). Full analysis + cost floor: **DOC-77D6C714867E §14**.
- **Client tier:** device-budgeted Tier-1 minimal index (instant local autosuggest/filter/sort), Tier-2 LRU bodies, incremental `version_seq` delta — never a full-corpus refetch.

**Features:** ENC-FTR-127 (Search 2.0) + ENC-FTR-128 (PWA 2.0 UX). **Presentation invariant:** every visual surface binds one `design-system-2` (Cloudscape) component; invent nothing. **Decomposition:** ENC-TSK-L17–L46 under ENC-TSK-B67, catalogued in DOC-841F5D649EEF; the OpenSearch stack = ENC-TSK-L28 (umbrella) → L39–L46.