# DOC-2B7AF00D8FB2 DVP-PLN-007 Wave B research dispatch prompts

**Project**: devops
**Related**: DVP-PLN-007, DVP-FTR-098, DVP-TSK-811, DVP-TSK-812, DVP-TSK-813, DVP-TSK-814, DVP-TSK-815, DVP-TSK-816, DVP-TSK-817, DVP-TSK-818, DOC-F5EF46453ABB, DOC-5132058DFFAB
**Author**: claude-opus-5-5 (Claude Code desktop), built from the Wave A ledger DOC-F5EF46453ABB
**Created**: 2026-10-10

Eight self-contained prompts, one per Wave B task, for claude.ai research agents (Sonnet 5, Research on, Enceladus connector enabled). Each prompt carries its task's acceptance criteria verbatim, the Wave A baseline for its design area, state-of-the-art research questions, the output skeleton and the governed delivery steps. Each agent publishes its own doc and closes its own task. Prompt bodies are indented four spaces; strip the indent when copying (the artifact page copies them clean).

```yaml
dispatch:
  - {wb: W-B1, task: DVP-TSK-811, area: auth, priority: P1, model: sonnet-5}
  - {wb: W-B2, task: DVP-TSK-812, area: shell, priority: P1, model: sonnet-5}
  - {wb: W-B3, task: DVP-TSK-813, area: md, priority: P2, model: sonnet-5}
  - {wb: W-B4, task: DVP-TSK-814, area: search, priority: P1, model: sonnet-5}
  - {wb: W-B5, task: DVP-TSK-815, area: feed, priority: P1, model: sonnet-5}
  - {wb: W-B6, task: DVP-TSK-816, area: schema_form, priority: P1, model: sonnet-5}
  - {wb: W-B7, task: DVP-TSK-817, area: recipes, priority: P2, model: sonnet-5}
  - {wb: W-B8, task: DVP-TSK-818, area: gates, priority: P2, model: sonnet-5}
```

## W-B1 auth (DVP-TSK-811)

    # W-B1 research: auth -- DVP-TSK-811 (DVP-PLN-007 Wave B)
    Recommended setup: Claude Sonnet 5, Research (Advanced) on, Enceladus connector enabled.

    You are a research agent for io's Enceladus program. Research how io's four stacks should evolve authentication and authorization from what they do today to the 2025-2026 state of the art, ending in one candidate canonical API for a shared auth package every stack can consume. Anchor on the INT-TSK-238 dual-path authorizer lineage: agents and humans reach the same handlers as distinguishable principals.

    ## Program context (ground truth as of 2026-10-10)
    ```yaml
    program: DVP-FTR-098 cross-stack UI convergence (idea DOC-5132058DFFAB, plan DVP-PLN-007)
    north_star: every action an agent can execute through an MCP surface is executable by a human in that stack's UI (parity diff = capability registry vs UI route manifest, enforced in CI)
    delivery_model: one versioned kit package per design area (auth, shell, md, search, feed, schema_form, recipes, gates); each stack pins a version; an improvement ships as a kit bump plus one PR per stack. Package home and naming are undecided, so write it as @io-kit/<area>.
    stacks:
      enceladus.jreese.net: React + Vite + Tailwind 4 + TanStack Query (frontend/ui-v2); AWS Cognito, Lambda, API Gateway, CloudFront, AppSync Events, DynamoDB
      ai.vagamod.io: Next.js app router + next-auth v5 (Keycloak OIDC) + Tailwind 3 + TanStack Query/Table; SST on AWS
      think.thepup.io: React + Vite (JS), react-router 6, vite-plugin-pwa; fronts the io-graph MCP surface
      coach.thepup.io: React + Vite (JS); carries the newest feed, auth-boundary and caching decisions
    constraints: iOS home-screen PWA is a first-class target; AWS-native backends; stacks deploy independently; agents and humans call the same governed HTTP handlers (MCP is a serialization adapter over them)
    wave_a_audits: {enceladus: DOC-AEF68227FEBB, vagamod: DOC-85B6774DAC96, think: DOC-90930433E582, coach: DOC-7789FF132F90, mcp_capability_inventory: DOC-04829C0677A3, ledger: DOC-F5EF46453ABB}
    ```

    ## Current state of auth (Wave A audits, snapshots at origin/main 2026-10-08)
    ```yaml
    enceladus: "partial. Cognito Hosted UI code flow; the code is exchanged server-side in the auth_refresh Lambda; HttpOnly id_token and refresh cookies; a fail-closed session probe gates the app. Nothing in the client calls the refresh route (open ENC-ISS-546: mid-session expiry with no re-auth surface). Lambda@Edge verifies legacy paths. Group checks are server-side only (io-dev-admin gate in graph_query_api; three-gate escalation decide). No execute-vs-dry-run rights."
    vagamod: "partial. next-auth v5 beta with Keycloak OIDC, not Cognito; server-side refresh with an explicit 401 on RefreshTokenError; a BFF proxy attaches the Bearer token; MCP has a separate OAuth 2.1 PKCE path; roles are library-membership roles (owner/editor/viewer)."
    think: "partial. Hand-written Cognito authorization-code + PKCE; tokens in localStorage; proactive silent refresh 5 minutes before IdToken expiry plus one 401-triggered retry; no group claims read anywhere."
    coach: "yes. PKCE on the shared pool us-west-2_y6bHKpNZN with its own app client; tokens in three localStorage keys; silent refresh ported from think; a per-route group map enforced inside the Lambda, no gateway authorizer."
    mcp_side: "INT-TSK-238 dual-path authorizer: internal API key (agents) or Cognito JWT (humans) on the same handlers."
    ```

    ## Acceptance criteria (verbatim from DVP-TSK-811; your only checklist)
    - AC1 A docstore document (subtype doc, keyword research, area auth) produced by a claude.ai Research session covers current best practice (2024-2026) for Cognito-backed SPA/PWA auth: session and refresh handling, group-based authorization, dual-path (API key vs JWT) posture, token storage on iOS PWA, and shared-package patterns for auth across multiple independent frontends
    - AC2 Documented vs inferred claims are marked; sources cited; recommendations are written as a candidate canonical API for the kit auth package
    - AC3 Edges to DVP-PLN-007 and DVP-FTR-098

    ## Research questions (state of the art and the evolution path)
    1. Token storage for browser apps: BFF with HttpOnly cookies vs in-memory tokens with refresh-token rotation vs localStorage. Where does the IETF 'OAuth 2.0 for Browser-Based Applications' BCP stand, and can DPoP (RFC 9449) or other sender-constrained tokens work with Cognito?
    2. iOS home-screen PWAs: storage partitioning, ITP eviction and cookie behaviour in standalone mode, and what that means for refresh tokens and silent refresh.
    3. Cognito features added 2024-2026 (managed login, refresh-token rotation, passkeys/WebAuthn, token revocation, pre-token-generation claim customization, M2M client credentials): which of them retire hand-written code in the stacks?
    4. Authorization models: RBAC vs ABAC vs ReBAC (Amazon Verified Permissions/Cedar, OpenFGA/Zanzibar). How to define per-action 'dry-run vs execute' rights once, enforce them on the server, and let the UI read the same policy to show, disable or hide actions.
    5. Dual-path posture: the MCP authorization spec (OAuth 2.1, protected resource metadata RFC 9728, resource indicators RFC 8707), M2M and agent-identity trends, and keeping agent and human principals distinguishable in audit logs while they hit the same handlers.
    6. One auth package across React/Vite SPAs and a Next.js app with two IdPs (Cognito and Keycloak): framework-agnostic core plus adapters, cross-tab session sync, logout and revocation, testability.

    ## Research method
    1. Start from the baseline above. If you can reach the Enceladus connector, read the `auth` cell in each Wave A audit for detail. Do not re-audit code.
    2. Survey the state of the art with a 2025-2026 source window: specs and RFCs, official docs and release notes, maintainer posts, conference talks, credible engineering write-ups. Date every source; use pre-2024 sources only for foundations.
    3. Give every technique a maturity ring (adopt | trial | assess | hold) with the reason, so emerging trends stay separate from what is production-ready.
    4. Evaluate each stack's gap to the state of the art, then lay out the evolution in three stages: `stage_1_converge` (adopt the best of what the four stacks already have), `stage_2_sota` (uplift beyond it), `stage_3_watch` (emerging, not yet adoptable).
    5. Prefer AWS-native services and open standards. If you recommend a third-party service, name its lock-in and exit cost.
    6. Mark every claim `[DOC]` (backed by a cited source or a Wave A audit) or `[INF]` (your inference). Use fenced YAML blocks, not pipe tables. Aim for 12-25 KB.

    ## Output document (use this skeleton exactly)
    ```
    # DVP-TSK-811 W-B1 Research: auth -- current state to state of the art

    **Project**: devops
    **Related**: DVP-TSK-811, DVP-PLN-007, DVP-FTR-098, DOC-5132058DFFAB, DOC-F5EF46453ABB, INT-TSK-238
    **Author**: claude.ai research agent <your ENC-SES id>, <model>
    **Created**: <today's date>

    ## 0. Scope, method and source window
    ## 1. Current state across stacks (baseline)
    ## 2. State of the art, 2025-2026 (per technique: what, why now, maturity ring, sources)
    ## 3. Gap evaluation per stack (YAML: stack -> {current, sota_target, gap, effort: S|M|L, risk})
    ## 4. Evolution path (YAML: stage_1_converge, stage_2_sota, stage_3_watch)
    ## 5. Candidate canonical API for @io-kit/auth (TypeScript signatures and data contracts)
    ## 6. Dual-path principal model (agent vs human on the same handlers)
    ## 7. iOS PWA token-storage findings
    ## 8. Open decisions for io
    ## Inference register
    ## Sources (title, publisher, date, URL)
    ```
    Section 5 starting point, to refine or replace: `createAuthClient(config), useSession(), can(action, mode: 'dry_run' | 'execute'), authFetch()`.

    ## Delivery (Enceladus governance; task DVP-TSK-811 is your only checklist)
    Run these steps once the document is final. If your research mode cannot call tools, end your reply with the complete document in one markdown block followed by the line `READY TO PUBLISH`; when io replies "publish", run the steps then.
    1. `connection_health` -> governance_hash. Pass it on every write.
    2. `coordination` agent.type.list -> pick the claude.ai-webui type for your model (Sonnet 5 = ENC-AGT-00D). Then agent.register `{agent_type_id, runtime: "claude_ai_webui", project_id: "devops"}` and agent.claim `{session_id}`. Keep session_id and sci. Every write needs sci; checkout, advance and worklog also need provider = your session_id. `advance_task_status` takes sci and provider, not active_agent_session_id.
    3. `tracker_get DVP-TSK-811`. If components is empty, `tracker_set` components = ["comp-devops-governance"]. Then `checkout_task DVP-TSK-811`.
    4. `documents_put` `{project_id: "devops", document_subtype: "doc", title, content, keywords: ["research", "auth", "state-of-the-art", "convergence", "dvp-pln-007"], related_items: [every id on the Related line], governance_hash}`. Keep the returned DOC id.
    5. For each acceptance criterion (criterion_index 0..2): `tracker_set_acceptance_evidence` `{record_id: "DVP-TSK-811", criterion_index, evidence: "<DOC id> section <n>: <one-line fact>", evidence_acceptance: true, governance_hash, provider}`. Stamp only what the document satisfies; otherwise fix the document first (`documents_patch` with the full content).
    6. `advance_task_status DVP-TSK-811` -> `coding-complete` with transition_evidence `{documentation_evidence: [DOC id]}`, then -> `closed` with transition_evidence `{no_code_evidence: "<what you produced and how you checked it>", documentation_evidence: [DOC id]}`.
    7. `append_worklog DVP-TSK-811` "[END] <DOC id>: <three-line summary>" (needs governance_hash, provider, sci), then `coordination` agent.retire `{session_id}`.
    Do not modify DVP-PLN-007 or any other record. Never paste credentials or tokens anywhere.

    Final reply to io: the DOC id, the task status, and your top five recommendations, one line each.

## W-B2 shell (DVP-TSK-812)

    # W-B2 research: shell -- DVP-TSK-812 (DVP-PLN-007 Wave B)
    Recommended setup: Claude Sonnet 5, Research (Advanced) on, Enceladus connector enabled.

    You are a research agent for io's Enceladus program. Research how the four stacks' app shells (frame, navigation, menus, responsive and mobile layout, theme tokens, PWA install and offline behaviour) should evolve into one state-of-the-art shell package. Parity matters here: navigation has to grow with every MCP surface a stack fronts instead of being hard-coded.

    ## Program context (ground truth as of 2026-10-10)
    ```yaml
    program: DVP-FTR-098 cross-stack UI convergence (idea DOC-5132058DFFAB, plan DVP-PLN-007)
    north_star: every action an agent can execute through an MCP surface is executable by a human in that stack's UI (parity diff = capability registry vs UI route manifest, enforced in CI)
    delivery_model: one versioned kit package per design area (auth, shell, md, search, feed, schema_form, recipes, gates); each stack pins a version; an improvement ships as a kit bump plus one PR per stack. Package home and naming are undecided, so write it as @io-kit/<area>.
    stacks:
      enceladus.jreese.net: React + Vite + Tailwind 4 + TanStack Query (frontend/ui-v2); AWS Cognito, Lambda, API Gateway, CloudFront, AppSync Events, DynamoDB
      ai.vagamod.io: Next.js app router + next-auth v5 (Keycloak OIDC) + Tailwind 3 + TanStack Query/Table; SST on AWS
      think.thepup.io: React + Vite (JS), react-router 6, vite-plugin-pwa; fronts the io-graph MCP surface
      coach.thepup.io: React + Vite (JS); carries the newest feed, auth-boundary and caching decisions
    constraints: iOS home-screen PWA is a first-class target; AWS-native backends; stacks deploy independently; agents and humans call the same governed HTTP handlers (MCP is a serialization adapter over them)
    wave_a_audits: {enceladus: DOC-AEF68227FEBB, vagamod: DOC-85B6774DAC96, think: DOC-90930433E582, coach: DOC-7789FF132F90, mcp_capability_inventory: DOC-04829C0677A3, ledger: DOC-F5EF46453ABB}
    ```

    ## Current state of shell (Wave A audits, snapshots at origin/main 2026-10-08)
    ```yaml
    enceladus: "yes. Tailwind 4 @theme fed by design-system-2 tokens; lucide icons; vite-plugin-pwa 1.3 with a service-worker update prompt; 48rem breakpoint, bottom nav on mobile, safe-area insets; command palette; 200 KB gz bundle budget. Four nav entries are placeholder stubs."
    vagamod: "yes. Next.js; Tailwind 3; cmdk command palette; sidebar + header + separate mobile nav; library (tenant) switcher; session guard. Theme tokens not examined."
    think: "yes. One NAV array renders a desktop left rail and a narrow-screen bottom nav; hard-coded to five io-graph tabs with no extension point; CSS-variable tokens; vite-plugin-pwa 0.21."
    coach: "yes. Viewport-height flex column with a non-scrolling header beside one inner scroller, because position: sticky failed on iOS Safari (INT-ISS-096); safe-area handled in the AppBar; a single route that switches on Cognito group."
    tokens_today: "two token sources (enceladus design-system-2, intelligence frontend/design-system); earlier canvas palette in DOC-3E8F94E6B1E2 section 3.6 (dark ground, IBM Plex Mono/Sans, rust accent)."
    ```

    ## Acceptance criteria (verbatim from DVP-TSK-812; your only checklist)
    - AC1 A docstore document (subtype doc, keyword research, area shell) covers current best practice for app shell, navigation, menus, responsive and mobile-first layout, theme tokens, and PWA install/offline behavior for multi-stack React/Vite frontends sharing one shell package
    - AC2 Documented vs inferred claims are marked; sources cited; recommendations are written as a candidate canonical API for the kit shell package
    - AC3 Edges to DVP-PLN-007 and DVP-FTR-098

    ## Research questions (state of the art and the evolution path)
    1. Design tokens: the W3C Design Tokens Community Group format and its stability, Style Dictionary-style pipelines, Tailwind 4 CSS-first @theme, OKLCH palettes, light-dark() and color-mix(); one token source themed per stack.
    2. Shell and navigation: navigation generated from a registry or manifest (so nav follows the capability registry), command palettes as primary navigation, adaptive rail / bottom bar / drawer, the View Transitions and Navigation APIs, popover and anchor positioning, container queries.
    3. iOS and mobile PWA in 2025-2026: current Safari standalone capabilities, Declarative Web Push, dvh/svh/lvh units, safe-area handling, scroll containers vs sticky, install prompts and standalone detection.
    4. Offline and service workers: Workbox's maintenance status, vite-plugin-pwa vs a hand-written worker, update UX, per-route caching strategy, navigation preload.
    5. Packaging one shell for React/Vite SPAs and a Next.js app router app: headless component layers (React Aria Components, Radix, Base UI, Ark UI), copy-in (shadcn/ui style) vs versioned package, CSS cascade layers, RSC compatibility, bundle budgets.
    6. Accessibility baseline for shells (WCAG 2.2: focus, target size, reduced motion).

    ## Research method
    1. Start from the baseline above. If you can reach the Enceladus connector, read the `shell` cell in each Wave A audit for detail. Do not re-audit code.
    2. Survey the state of the art with a 2025-2026 source window: specs and RFCs, official docs and release notes, maintainer posts, conference talks, credible engineering write-ups. Date every source; use pre-2024 sources only for foundations.
    3. Give every technique a maturity ring (adopt | trial | assess | hold) with the reason, so emerging trends stay separate from what is production-ready.
    4. Evaluate each stack's gap to the state of the art, then lay out the evolution in three stages: `stage_1_converge` (adopt the best of what the four stacks already have), `stage_2_sota` (uplift beyond it), `stage_3_watch` (emerging, not yet adoptable).
    5. Prefer AWS-native services and open standards. If you recommend a third-party service, name its lock-in and exit cost.
    6. Mark every claim `[DOC]` (backed by a cited source or a Wave A audit) or `[INF]` (your inference). Use fenced YAML blocks, not pipe tables. Aim for 12-25 KB.

    ## Output document (use this skeleton exactly)
    ```
    # DVP-TSK-812 W-B2 Research: shell -- current state to state of the art

    **Project**: devops
    **Related**: DVP-TSK-812, DVP-PLN-007, DVP-FTR-098, DOC-5132058DFFAB, DOC-F5EF46453ABB, DOC-3E8F94E6B1E2
    **Author**: claude.ai research agent <your ENC-SES id>, <model>
    **Created**: <today's date>

    ## 0. Scope, method and source window
    ## 1. Current state across stacks (baseline)
    ## 2. State of the art, 2025-2026 (per technique: what, why now, maturity ring, sources)
    ## 3. Gap evaluation per stack (YAML: stack -> {current, sota_target, gap, effort: S|M|L, risk})
    ## 4. Evolution path (YAML: stage_1_converge, stage_2_sota, stage_3_watch)
    ## 5. Candidate canonical API for @io-kit/shell (TypeScript signatures and data contracts)
    ## 6. Navigation registry contract (how nav derives from a route manifest or capability registry)
    ## 7. Open decisions for io
    ## Inference register
    ## Sources (title, publisher, date, URL)
    ```
    Section 5 starting point, to refine or replace: `<KitShell nav={registry} />, defineNavRegistry(), a tokens package with per-stack themes, useBreakpoint()`.

    ## Delivery (Enceladus governance; task DVP-TSK-812 is your only checklist)
    Run these steps once the document is final. If your research mode cannot call tools, end your reply with the complete document in one markdown block followed by the line `READY TO PUBLISH`; when io replies "publish", run the steps then.
    1. `connection_health` -> governance_hash. Pass it on every write.
    2. `coordination` agent.type.list -> pick the claude.ai-webui type for your model (Sonnet 5 = ENC-AGT-00D). Then agent.register `{agent_type_id, runtime: "claude_ai_webui", project_id: "devops"}` and agent.claim `{session_id}`. Keep session_id and sci. Every write needs sci; checkout, advance and worklog also need provider = your session_id. `advance_task_status` takes sci and provider, not active_agent_session_id.
    3. `tracker_get DVP-TSK-812`. If components is empty, `tracker_set` components = ["comp-devops-governance"]. Then `checkout_task DVP-TSK-812`.
    4. `documents_put` `{project_id: "devops", document_subtype: "doc", title, content, keywords: ["research", "shell", "state-of-the-art", "convergence", "dvp-pln-007"], related_items: [every id on the Related line], governance_hash}`. Keep the returned DOC id.
    5. For each acceptance criterion (criterion_index 0..2): `tracker_set_acceptance_evidence` `{record_id: "DVP-TSK-812", criterion_index, evidence: "<DOC id> section <n>: <one-line fact>", evidence_acceptance: true, governance_hash, provider}`. Stamp only what the document satisfies; otherwise fix the document first (`documents_patch` with the full content).
    6. `advance_task_status DVP-TSK-812` -> `coding-complete` with transition_evidence `{documentation_evidence: [DOC id]}`, then -> `closed` with transition_evidence `{no_code_evidence: "<what you produced and how you checked it>", documentation_evidence: [DOC id]}`.
    7. `append_worklog DVP-TSK-812` "[END] <DOC id>: <three-line summary>" (needs governance_hash, provider, sci), then `coordination` agent.retire `{session_id}`.
    Do not modify DVP-PLN-007 or any other record. Never paste credentials or tokens anywhere.

    Final reply to io: the DOC id, the task status, and your top five recommendations, one line each.

## W-B3 md (DVP-TSK-813)

    # W-B3 research: md -- DVP-TSK-813 (DVP-PLN-007 Wave B)
    Recommended setup: Claude Sonnet 5, Research (Advanced) on, Enceladus connector enabled.

    You are a research agent for io's Enceladus program. Research how markdown rendering across the stacks should evolve into one state-of-the-art md package that renders Enceladus docstore documents natively (metadata block, YAML blocks, record-ID links, [DOC]/[INF] claim tags, section anchors), safely, and fast on large documents.

    ## Program context (ground truth as of 2026-10-10)
    ```yaml
    program: DVP-FTR-098 cross-stack UI convergence (idea DOC-5132058DFFAB, plan DVP-PLN-007)
    north_star: every action an agent can execute through an MCP surface is executable by a human in that stack's UI (parity diff = capability registry vs UI route manifest, enforced in CI)
    delivery_model: one versioned kit package per design area (auth, shell, md, search, feed, schema_form, recipes, gates); each stack pins a version; an improvement ships as a kit bump plus one PR per stack. Package home and naming are undecided, so write it as @io-kit/<area>.
    stacks:
      enceladus.jreese.net: React + Vite + Tailwind 4 + TanStack Query (frontend/ui-v2); AWS Cognito, Lambda, API Gateway, CloudFront, AppSync Events, DynamoDB
      ai.vagamod.io: Next.js app router + next-auth v5 (Keycloak OIDC) + Tailwind 3 + TanStack Query/Table; SST on AWS
      think.thepup.io: React + Vite (JS), react-router 6, vite-plugin-pwa; fronts the io-graph MCP surface
      coach.thepup.io: React + Vite (JS); carries the newest feed, auth-boundary and caching decisions
    constraints: iOS home-screen PWA is a first-class target; AWS-native backends; stacks deploy independently; agents and humans call the same governed HTTP handlers (MCP is a serialization adapter over them)
    wave_a_audits: {enceladus: DOC-AEF68227FEBB, vagamod: DOC-85B6774DAC96, think: DOC-90930433E582, coach: DOC-7789FF132F90, mcp_capability_inventory: DOC-04829C0677A3, ledger: DOC-F5EF46453ABB}
    ```

    ## Current state of md (Wave A audits, snapshots at origin/main 2026-10-08)
    ```yaml
    enceladus: "partial. Hand-rolled block + inline parser; auto-links ENC-/DOC- ids to routes; long-token wrapping; section outline and a section editor with a conflict view. Handles fences, headings, blockquotes, lists, links, inline code. No dangerouslySetInnerHTML: React escaping is the only sanitization."
    think: "yes. react-markdown 10 + react-syntax-highlighter + DOMPurify; a typed renderer registry keyed by renderer_hint (markdown, plaintext, archived capture, pdf, binary, external); body fetched from a presigned URL with one 403 retry. Generic CommonMark/GFM; no docstore-convention handling."
    vagamod: "no renderer."
    coach: "no renderer (plain-text notes)."
    docstore_conventions: "H1 '# <ID> Title'; metadata lines **Project** / **Related** / **Author** / **Created**; fenced YAML preferred over pipe tables (ENC-LSN-026); [DOC]/[INF] claim tags; section edits addressed by heading path and block id; documents are commonly 15-80 KB."
    ```

    ## Acceptance criteria (verbatim from DVP-TSK-813; your only checklist)
    - AC1 A docstore document (subtype doc, keyword research, area md) covers current best practice for rendering markdown in React PWAs: parser choice, security (sanitization), code fences and YAML blocks, metadata/frontmatter conventions, large-document performance, and section-anchor linking, with attention to the Enceladus docstore conventions (metadata block, ENC-LSN-026 YAML-over-tables)
    - AC2 Documented vs inferred claims are marked; sources cited; recommendations are written as a candidate canonical API for the kit md package
    - AC3 Edges to DVP-PLN-007 and DVP-FTR-098

    ## Research questions (state of the art and the evolution path)
    1. Parser landscape: unified/remark/rehype (micromark), markdown-it, marked, Markdoc, MDX 3, and streaming renderers built for LLM output. Compare CommonMark/GFM compliance, extensibility, bundle size and speed.
    2. Security for agent-authored content: rehype-sanitize vs DOMPurify, Trusted Types, the HTML Sanitizer API (setHTML) and its browser status, URL-protocol allow-lists, raw-HTML policy.
    3. Code and YAML: Shiki (fine-grained bundles, worker or build-time highlighting) vs highlight.js/Prism; YAML blocks rendered as structured, collapsible views vs plain code; mermaid diagrams.
    4. Docstore conventions as syntax: remark/rehype plugins vs remark-directive for ID auto-linking (ENC-TSK-..., DOC-...), claim-tag badges, and turning the metadata block into a header card.
    5. Large-document performance: incremental or virtualized rendering, parsing in a worker, per-section memoization, outline extraction, stable heading slugs, deep links to sections and block ids, section-level editing.
    6. Package shape: a pure renderer with a plugin registry and framework adapters; SSR/RSC compatibility for the Next.js stack.

    ## Research method
    1. Start from the baseline above. If you can reach the Enceladus connector, read the `md` cell in each Wave A audit for detail. Do not re-audit code.
    2. Survey the state of the art with a 2025-2026 source window: specs and RFCs, official docs and release notes, maintainer posts, conference talks, credible engineering write-ups. Date every source; use pre-2024 sources only for foundations.
    3. Give every technique a maturity ring (adopt | trial | assess | hold) with the reason, so emerging trends stay separate from what is production-ready.
    4. Evaluate each stack's gap to the state of the art, then lay out the evolution in three stages: `stage_1_converge` (adopt the best of what the four stacks already have), `stage_2_sota` (uplift beyond it), `stage_3_watch` (emerging, not yet adoptable).
    5. Prefer AWS-native services and open standards. If you recommend a third-party service, name its lock-in and exit cost.
    6. Mark every claim `[DOC]` (backed by a cited source or a Wave A audit) or `[INF]` (your inference). Use fenced YAML blocks, not pipe tables. Aim for 12-25 KB.

    ## Output document (use this skeleton exactly)
    ```
    # DVP-TSK-813 W-B3 Research: md -- current state to state of the art

    **Project**: devops
    **Related**: DVP-TSK-813, DVP-PLN-007, DVP-FTR-098, DOC-5132058DFFAB, DOC-F5EF46453ABB
    **Author**: claude.ai research agent <your ENC-SES id>, <model>
    **Created**: <today's date>

    ## 0. Scope, method and source window
    ## 1. Current state across stacks (baseline)
    ## 2. State of the art, 2025-2026 (per technique: what, why now, maturity ring, sources)
    ## 3. Gap evaluation per stack (YAML: stack -> {current, sota_target, gap, effort: S|M|L, risk})
    ## 4. Evolution path (YAML: stage_1_converge, stage_2_sota, stage_3_watch)
    ## 5. Candidate canonical API for @io-kit/md (TypeScript signatures and data contracts)
    ## 6. Docstore convention rendering spec (each convention -> rendering rule)
    ## 7. Open decisions for io
    ## Inference register
    ## Sources (title, publisher, date, URL)
    ```
    Section 5 starting point, to refine or replace: `<KitMarkdown source plugins={[docstore(), idLinks(resolver)]} />, parseOutline(source), sanitizePolicy`.

    ## Delivery (Enceladus governance; task DVP-TSK-813 is your only checklist)
    Run these steps once the document is final. If your research mode cannot call tools, end your reply with the complete document in one markdown block followed by the line `READY TO PUBLISH`; when io replies "publish", run the steps then.
    1. `connection_health` -> governance_hash. Pass it on every write.
    2. `coordination` agent.type.list -> pick the claude.ai-webui type for your model (Sonnet 5 = ENC-AGT-00D). Then agent.register `{agent_type_id, runtime: "claude_ai_webui", project_id: "devops"}` and agent.claim `{session_id}`. Keep session_id and sci. Every write needs sci; checkout, advance and worklog also need provider = your session_id. `advance_task_status` takes sci and provider, not active_agent_session_id.
    3. `tracker_get DVP-TSK-813`. If components is empty, `tracker_set` components = ["comp-devops-governance"]. Then `checkout_task DVP-TSK-813`.
    4. `documents_put` `{project_id: "devops", document_subtype: "doc", title, content, keywords: ["research", "md", "state-of-the-art", "convergence", "dvp-pln-007"], related_items: [every id on the Related line], governance_hash}`. Keep the returned DOC id.
    5. For each acceptance criterion (criterion_index 0..2): `tracker_set_acceptance_evidence` `{record_id: "DVP-TSK-813", criterion_index, evidence: "<DOC id> section <n>: <one-line fact>", evidence_acceptance: true, governance_hash, provider}`. Stamp only what the document satisfies; otherwise fix the document first (`documents_patch` with the full content).
    6. `advance_task_status DVP-TSK-813` -> `coding-complete` with transition_evidence `{documentation_evidence: [DOC id]}`, then -> `closed` with transition_evidence `{no_code_evidence: "<what you produced and how you checked it>", documentation_evidence: [DOC id]}`.
    7. `append_worklog DVP-TSK-813` "[END] <DOC id>: <three-line summary>" (needs governance_hash, provider, sci), then `coordination` agent.retire `{session_id}`.
    Do not modify DVP-PLN-007 or any other record. Never paste credentials or tokens anywhere.

    Final reply to io: the DOC id, the task status, and your top five recommendations, one line each.

## W-B4 search (DVP-TSK-814)

    # W-B4 research: search -- DVP-TSK-814 (DVP-PLN-007 Wave B)
    Recommended setup: Claude Sonnet 5, Research (Advanced) on, Enceladus connector enabled.

    You are a research agent for io's Enceladus program. Research how search UX over hybrid retrieval (vector + keyword + graph, RRF fusion) should evolve from what the stacks have into a state-of-the-art search package. Keep 'converge to best existing' strictly apart from 'improve beyond' (DOC-5132058DFFAB, risk scope_creep): only the first is in this program's scope; the second becomes a recommendation list.

    ## Program context (ground truth as of 2026-10-10)
    ```yaml
    program: DVP-FTR-098 cross-stack UI convergence (idea DOC-5132058DFFAB, plan DVP-PLN-007)
    north_star: every action an agent can execute through an MCP surface is executable by a human in that stack's UI (parity diff = capability registry vs UI route manifest, enforced in CI)
    delivery_model: one versioned kit package per design area (auth, shell, md, search, feed, schema_form, recipes, gates); each stack pins a version; an improvement ships as a kit bump plus one PR per stack. Package home and naming are undecided, so write it as @io-kit/<area>.
    stacks:
      enceladus.jreese.net: React + Vite + Tailwind 4 + TanStack Query (frontend/ui-v2); AWS Cognito, Lambda, API Gateway, CloudFront, AppSync Events, DynamoDB
      ai.vagamod.io: Next.js app router + next-auth v5 (Keycloak OIDC) + Tailwind 3 + TanStack Query/Table; SST on AWS
      think.thepup.io: React + Vite (JS), react-router 6, vite-plugin-pwa; fronts the io-graph MCP surface
      coach.thepup.io: React + Vite (JS); carries the newest feed, auth-boundary and caching decisions
    constraints: iOS home-screen PWA is a first-class target; AWS-native backends; stacks deploy independently; agents and humans call the same governed HTTP handlers (MCP is a serialization adapter over them)
    wave_a_audits: {enceladus: DOC-AEF68227FEBB, vagamod: DOC-85B6774DAC96, think: DOC-90930433E582, coach: DOC-7789FF132F90, mcp_capability_inventory: DOC-04829C0677A3, ledger: DOC-F5EF46453ABB}
    ```

    ## Current state of search (Wave A audits, snapshots at origin/main 2026-10-08)
    ```yaml
    enceladus: "partial. Two tiers: local first, then hybrid via GET /api/v1/tracker/graphsearch?search_type=hybrid, merged with a tier badge; the response carries signal_availability {vector, graph, keyword} and per_signal_ranks; saved searches, property filters, recently viewed. No per-signal toggle UI, no pin-as-related."
    think: "partial. Single query box with URL-owned params; server-side RRF of vector + keyword + graph (personalized PageRank); a per-signal readout on every result; type and source facets. No signal toggles."
    vagamod: "partial. Fuse.js over the whole object list, fetched once per session; facet counts computed client-side; a server /search exists but the UI never calls it. Lexical only."
    coach: "none."
    live_degraded_case: "the Enceladus graph index currently reports signals {vector: true, keyword: true, graph: false} because no graph projection is configured, so degraded mode is a present-day case."
    ```

    ## Acceptance criteria (verbatim from DVP-TSK-814; your only checklist)
    - AC1 A docstore document (subtype doc, keyword research, area search) covers current best practice for search UX over hybrid retrieval (vector + keyword + graph, RRF fusion): query input, signal toggles, result tables with per-signal evidence, pin/select-to-context flows, latency expectations, and degraded-mode behavior when a signal is unavailable
    - AC2 The document separates 'converge to best existing' from 'improve beyond' per DOC-5132058DFFAB risk scope_creep
    - AC3 Documented vs inferred claims are marked; sources cited; candidate canonical API for the kit search package; edges to DVP-PLN-007 and DVP-FTR-098

    ## Research questions (state of the art and the evolution path)
    1. Hybrid retrieval as users experience it in 2025-2026: RRF vs weighted fusion vs learned or cross-encoder reranking and late interaction (ColBERT-style); how Elastic, OpenSearch, Vespa, Algolia and enterprise or AI search products expose them.
    2. Explaining results: per-signal contribution, rank evidence, highlights and 'why this result'; when signal toggles help users and when they are noise.
    3. Query input: typeahead, structured filter syntax, natural language to structured filters, URL-owned state, saved searches.
    4. Result tables and selection: multi-select, pin-as-related (writing an edge), 'add to context' flows that hand results to an agent, keyboard ergonomics.
    5. Latency: p50/p95 budgets for instant and hybrid tiers, local-first then server merge (the Enceladus pattern), streaming and progressive results.
    6. Degraded mode: showing an unavailable signal, re-weighting fusion, and keeping result quality honest to the user.

    ## Research method
    1. Start from the baseline above. If you can reach the Enceladus connector, read the `search` cell in each Wave A audit for detail. Do not re-audit code.
    2. Survey the state of the art with a 2025-2026 source window: specs and RFCs, official docs and release notes, maintainer posts, conference talks, credible engineering write-ups. Date every source; use pre-2024 sources only for foundations.
    3. Give every technique a maturity ring (adopt | trial | assess | hold) with the reason, so emerging trends stay separate from what is production-ready.
    4. Evaluate each stack's gap to the state of the art, then lay out the evolution in three stages: `stage_1_converge` (adopt the best of what the four stacks already have), `stage_2_sota` (uplift beyond it), `stage_3_watch` (emerging, not yet adoptable).
    5. Prefer AWS-native services and open standards. If you recommend a third-party service, name its lock-in and exit cost.
    6. Mark every claim `[DOC]` (backed by a cited source or a Wave A audit) or `[INF]` (your inference). Use fenced YAML blocks, not pipe tables. Aim for 12-25 KB.

    ## Output document (use this skeleton exactly)
    ```
    # DVP-TSK-814 W-B4 Research: search -- current state to state of the art

    **Project**: devops
    **Related**: DVP-TSK-814, DVP-PLN-007, DVP-FTR-098, DOC-5132058DFFAB, DOC-F5EF46453ABB
    **Author**: claude.ai research agent <your ENC-SES id>, <model>
    **Created**: <today's date>

    ## 0. Scope, method and source window
    ## 1. Current state across stacks (baseline)
    ## 2. State of the art, 2025-2026 (per technique: what, why now, maturity ring, sources)
    ## 3. Gap evaluation per stack (YAML: stack -> {current, sota_target, gap, effort: S|M|L, risk})
    ## 4. Evolution path (YAML: stage_1_converge, stage_2_sota, stage_3_watch)
    ## 5. Candidate canonical API for @io-kit/search (TypeScript signatures and data contracts)
    ## 6. Converge to best existing (in scope)
    ## 7. Improve beyond (recommendations, out of scope for this program)
    ## 8. Degraded-mode behaviour spec
    ## 9. Open decisions for io
    ## Inference register
    ## Sources (title, publisher, date, URL)
    ```
    Section 5 starting point, to refine or replace: `useHybridSearch({query, signals}), <ResultTable evidence />, onPin(result) -> relatedEdge, SignalAvailability`.

    ## Delivery (Enceladus governance; task DVP-TSK-814 is your only checklist)
    Run these steps once the document is final. If your research mode cannot call tools, end your reply with the complete document in one markdown block followed by the line `READY TO PUBLISH`; when io replies "publish", run the steps then.
    1. `connection_health` -> governance_hash. Pass it on every write.
    2. `coordination` agent.type.list -> pick the claude.ai-webui type for your model (Sonnet 5 = ENC-AGT-00D). Then agent.register `{agent_type_id, runtime: "claude_ai_webui", project_id: "devops"}` and agent.claim `{session_id}`. Keep session_id and sci. Every write needs sci; checkout, advance and worklog also need provider = your session_id. `advance_task_status` takes sci and provider, not active_agent_session_id.
    3. `tracker_get DVP-TSK-814`. If components is empty, `tracker_set` components = ["comp-devops-governance"]. Then `checkout_task DVP-TSK-814`.
    4. `documents_put` `{project_id: "devops", document_subtype: "doc", title, content, keywords: ["research", "search", "state-of-the-art", "convergence", "dvp-pln-007"], related_items: [every id on the Related line], governance_hash}`. Keep the returned DOC id.
    5. For each acceptance criterion (criterion_index 0..2): `tracker_set_acceptance_evidence` `{record_id: "DVP-TSK-814", criterion_index, evidence: "<DOC id> section <n>: <one-line fact>", evidence_acceptance: true, governance_hash, provider}`. Stamp only what the document satisfies; otherwise fix the document first (`documents_patch` with the full content).
    6. `advance_task_status DVP-TSK-814` -> `coding-complete` with transition_evidence `{documentation_evidence: [DOC id]}`, then -> `closed` with transition_evidence `{no_code_evidence: "<what you produced and how you checked it>", documentation_evidence: [DOC id]}`.
    7. `append_worklog DVP-TSK-814` "[END] <DOC id>: <three-line summary>" (needs governance_hash, provider, sci), then `coordination` agent.retire `{session_id}`.
    Do not modify DVP-PLN-007 or any other record. Never paste credentials or tokens anywhere.

    Final reply to io: the DOC id, the task status, and your top five recommendations, one line each.

## W-B5 feed (DVP-TSK-815)

    # W-B5 research: feed -- DVP-TSK-815 (DVP-PLN-007 Wave B)
    Recommended setup: Claude Sonnet 5, Research (Advanced) on, Enceladus connector enabled.

    You are a research agent for io's Enceladus program. Research the delta between what DOC-A5BCD6216666 already settles for card feeds and the 2025-2026 state of the art, and turn it into a shared feed package every stack can consume. Do not re-research what that document settles: state it first, then research only shared-package packaging, multi-stack data contracts and realtime transport.

    ## Program context (ground truth as of 2026-10-10)
    ```yaml
    program: DVP-FTR-098 cross-stack UI convergence (idea DOC-5132058DFFAB, plan DVP-PLN-007)
    north_star: every action an agent can execute through an MCP surface is executable by a human in that stack's UI (parity diff = capability registry vs UI route manifest, enforced in CI)
    delivery_model: one versioned kit package per design area (auth, shell, md, search, feed, schema_form, recipes, gates); each stack pins a version; an improvement ships as a kit bump plus one PR per stack. Package home and naming are undecided, so write it as @io-kit/<area>.
    stacks:
      enceladus.jreese.net: React + Vite + Tailwind 4 + TanStack Query (frontend/ui-v2); AWS Cognito, Lambda, API Gateway, CloudFront, AppSync Events, DynamoDB
      ai.vagamod.io: Next.js app router + next-auth v5 (Keycloak OIDC) + Tailwind 3 + TanStack Query/Table; SST on AWS
      think.thepup.io: React + Vite (JS), react-router 6, vite-plugin-pwa; fronts the io-graph MCP surface
      coach.thepup.io: React + Vite (JS); carries the newest feed, auth-boundary and caching decisions
    constraints: iOS home-screen PWA is a first-class target; AWS-native backends; stacks deploy independently; agents and humans call the same governed HTTP handlers (MCP is a serialization adapter over them)
    wave_a_audits: {enceladus: DOC-AEF68227FEBB, vagamod: DOC-85B6774DAC96, think: DOC-90930433E582, coach: DOC-7789FF132F90, mcp_capability_inventory: DOC-04829C0677A3, ledger: DOC-F5EF46453ABB}
    ```

    ## Current state of feed (Wave A audits, snapshots at origin/main 2026-10-08)
    ```yaml
    enceladus: "yes. TanStack Virtual 3.14 + TanStack Query + zustand; cursor-paginated warm start, delta feed by since-seq with a doc-seq cursor, insert-buffer store, virtualized list, scroll restore; AppSync Events WebSocket with 500ms-30s reconnect backoff, a gap_too_large signal and a liveness watchdog; IndexedDB cache. Realtime auth uses an AppSync API key in public client config."
    coach: "yes. GET /events in count mode and window mode (cap 200 + next_cursor); opaque base64url(sk) keyset cursor; signal-then-fetch live buffer over AppSync Events; newer-items pill. No TanStack Query, no virtualization, no IndexedDB, unsigned cursors."
    think: "yes. Cursor pages of 20, append-only; IntersectionObserver sentinel with a 400px rootMargin; sort toggle with a cursor-reset guard; per-view cache. No realtime path."
    vagamod: "no feed (virtualized tables only)."
    settled_by_DOC-A5BCD6216666: "read its 'Default architecture (reusable)' section and list what it settles (keyset cursor with has_more/next_cursor, sentinel trigger, newer-items pill, inline retry, TanStack Query, virtualization, IndexedDB persistence, since= newer fetch) before researching anything."
    ```

    ## Acceptance criteria (verbatim from DVP-TSK-815; your only checklist)
    - AC1 A docstore document (subtype doc, keyword research, area feed) covers current best practice for card-based feeds with low-latency updates: keyset cursor pagination, infinite scroll, realtime insert buffering, cache correctness under CloudFront, virtualization thresholds, and iOS PWA specifics, building on and not duplicating DOC-A5BCD6216666
    - AC2 The document states explicitly what DOC-A5BCD6216666 already settles and only researches the delta (shared-package packaging, multi-stack data-contract abstraction, websocket/SSE vs polling for realtime)
    - AC3 Documented vs inferred claims are marked; sources cited; candidate canonical API for the kit feed package; edges to DVP-PLN-007 and DVP-FTR-098

    ## Research questions (state of the art and the evolution path)
    1. Packaging a feed engine for several stacks: headless core (state machine) plus React bindings; TanStack Query v5 infinite queries vs a custom store; signals-based stores; how to test it.
    2. A multi-stack data contract: a FeedSource adapter (page(cursor), since(seq), subscribe()), opaque and signed cursors, ordering keys (ULID or sequence), dedupe and tombstones, schema evolution.
    3. Realtime transport in 2025-2026: AppSync Events and API Gateway WebSockets, SSE (including Lambda response streaming over HTTP/2-3), WebTransport status, long-poll; signal-then-fetch vs payload push; iOS suspension and reconnect; authenticating realtime channels with Cognito instead of an API key.
    4. Cache correctness under CloudFront: cache keys with cursors, private vs shared caching for per-user feeds, stale-while-revalidate, versioned keys vs invalidation.
    5. Virtualization thresholds and iOS PWA scroll: content-visibility: auto, scroll anchoring, momentum scroll, memory ceilings.
    6. Local-first sync engines (Zero/Replicache, ElectricSQL, TanStack DB, LiveStore and similar): is any a credible stage-2 uplift for a governed, AWS-native backend?

    ## Research method
    1. Start from the baseline above. If you can reach the Enceladus connector, read the `feed` cell in each Wave A audit for detail. Do not re-audit code.
    2. Survey the state of the art with a 2025-2026 source window: specs and RFCs, official docs and release notes, maintainer posts, conference talks, credible engineering write-ups. Date every source; use pre-2024 sources only for foundations.
    3. Give every technique a maturity ring (adopt | trial | assess | hold) with the reason, so emerging trends stay separate from what is production-ready.
    4. Evaluate each stack's gap to the state of the art, then lay out the evolution in three stages: `stage_1_converge` (adopt the best of what the four stacks already have), `stage_2_sota` (uplift beyond it), `stage_3_watch` (emerging, not yet adoptable).
    5. Prefer AWS-native services and open standards. If you recommend a third-party service, name its lock-in and exit cost.
    6. Mark every claim `[DOC]` (backed by a cited source or a Wave A audit) or `[INF]` (your inference). Use fenced YAML blocks, not pipe tables. Aim for 12-25 KB.

    ## Output document (use this skeleton exactly)
    ```
    # DVP-TSK-815 W-B5 Research: feed -- current state to state of the art

    **Project**: devops
    **Related**: DVP-TSK-815, DVP-PLN-007, DVP-FTR-098, DOC-5132058DFFAB, DOC-F5EF46453ABB, DOC-A5BCD6216666
    **Author**: claude.ai research agent <your ENC-SES id>, <model>
    **Created**: <today's date>

    ## 0. Scope, method and source window
    ## 1. Current state across stacks (baseline)
    ## 2. State of the art, 2025-2026 (per technique: what, why now, maturity ring, sources)
    ## 3. Gap evaluation per stack (YAML: stack -> {current, sota_target, gap, effort: S|M|L, risk})
    ## 4. Evolution path (YAML: stage_1_converge, stage_2_sota, stage_3_watch)
    ## 5. Candidate canonical API for @io-kit/feed (TypeScript signatures and data contracts)
    ## 6. What DOC-A5BCD6216666 already settles
    ## 7. Delta research: packaging, data contract, realtime transport
    ## 8. Open decisions for io
    ## Inference register
    ## Sources (title, publisher, date, URL)
    ```
    Section 5 starting point, to refine or replace: `createFeed(source: FeedSource), useFeed(key), <FeedList renderCard />, FeedSource { page, since, subscribe }`.

    ## Delivery (Enceladus governance; task DVP-TSK-815 is your only checklist)
    Run these steps once the document is final. If your research mode cannot call tools, end your reply with the complete document in one markdown block followed by the line `READY TO PUBLISH`; when io replies "publish", run the steps then.
    1. `connection_health` -> governance_hash. Pass it on every write.
    2. `coordination` agent.type.list -> pick the claude.ai-webui type for your model (Sonnet 5 = ENC-AGT-00D). Then agent.register `{agent_type_id, runtime: "claude_ai_webui", project_id: "devops"}` and agent.claim `{session_id}`. Keep session_id and sci. Every write needs sci; checkout, advance and worklog also need provider = your session_id. `advance_task_status` takes sci and provider, not active_agent_session_id.
    3. `tracker_get DVP-TSK-815`. If components is empty, `tracker_set` components = ["comp-devops-governance"]. Then `checkout_task DVP-TSK-815`.
    4. `documents_put` `{project_id: "devops", document_subtype: "doc", title, content, keywords: ["research", "feed", "state-of-the-art", "convergence", "dvp-pln-007"], related_items: [every id on the Related line], governance_hash}`. Keep the returned DOC id.
    5. For each acceptance criterion (criterion_index 0..2): `tracker_set_acceptance_evidence` `{record_id: "DVP-TSK-815", criterion_index, evidence: "<DOC id> section <n>: <one-line fact>", evidence_acceptance: true, governance_hash, provider}`. Stamp only what the document satisfies; otherwise fix the document first (`documents_patch` with the full content).
    6. `advance_task_status DVP-TSK-815` -> `coding-complete` with transition_evidence `{documentation_evidence: [DOC id]}`, then -> `closed` with transition_evidence `{no_code_evidence: "<what you produced and how you checked it>", documentation_evidence: [DOC id]}`.
    7. `append_worklog DVP-TSK-815` "[END] <DOC id>: <three-line summary>" (needs governance_hash, provider, sci), then `coordination` agent.retire `{session_id}`.
    Do not modify DVP-PLN-007 or any other record. Never paste credentials or tokens anywhere.

    Final reply to io: the DOC id, the task status, and your top five recommendations, one line each.

## W-B6 schema_form (DVP-TSK-816)

    # W-B6 research: schema_form -- DVP-TSK-816 (DVP-PLN-007 Wave B)
    Recommended setup: Claude Sonnet 5, Research (Advanced) on, Enceladus connector enabled.

    You are a research agent for io's Enceladus program. Define the baseline for a state-of-the-art schema-driven form package: given a tool contract, render a form, preview the exact resolved call (dry run), then execute. This is the core of agent/human parity: each of the 220 MCP actions in DOC-04829C0677A3 should become human-operable without hand-built UI. No stack has this today, so your research sets the baseline.

    ## Program context (ground truth as of 2026-10-10)
    ```yaml
    program: DVP-FTR-098 cross-stack UI convergence (idea DOC-5132058DFFAB, plan DVP-PLN-007)
    north_star: every action an agent can execute through an MCP surface is executable by a human in that stack's UI (parity diff = capability registry vs UI route manifest, enforced in CI)
    delivery_model: one versioned kit package per design area (auth, shell, md, search, feed, schema_form, recipes, gates); each stack pins a version; an improvement ships as a kit bump plus one PR per stack. Package home and naming are undecided, so write it as @io-kit/<area>.
    stacks:
      enceladus.jreese.net: React + Vite + Tailwind 4 + TanStack Query (frontend/ui-v2); AWS Cognito, Lambda, API Gateway, CloudFront, AppSync Events, DynamoDB
      ai.vagamod.io: Next.js app router + next-auth v5 (Keycloak OIDC) + Tailwind 3 + TanStack Query/Table; SST on AWS
      think.thepup.io: React + Vite (JS), react-router 6, vite-plugin-pwa; fronts the io-graph MCP surface
      coach.thepup.io: React + Vite (JS); carries the newest feed, auth-boundary and caching decisions
    constraints: iOS home-screen PWA is a first-class target; AWS-native backends; stacks deploy independently; agents and humans call the same governed HTTP handlers (MCP is a serialization adapter over them)
    wave_a_audits: {enceladus: DOC-AEF68227FEBB, vagamod: DOC-85B6774DAC96, think: DOC-90930433E582, coach: DOC-7789FF132F90, mcp_capability_inventory: DOC-04829C0677A3, ledger: DOC-F5EF46453ABB}
    ```

    ## Current state of schema_form (Wave A audits, snapshots at origin/main 2026-10-08)
    ```yaml
    all_stacks: "no generator anywhere. enceladus: hand-coded writes (record PATCH, task actions). vagamod: hand-written forms; zod schemas live separately on the MCP side; ids are minted server-side (generateId). think: hand-written per-action controls that call executeCall as a single step, then show the server's per-step echo. coach: one hand-built 511-line WritePage."
    contract_supply: "DOC-04829C0677A3 counts 220 actions on 7 MCP surfaces. Vagamod, io-finance, io-devops, io-travel and chosen-family expose per-tool JSON Schemas through MCP tools/list. Enceladus v2 (105 actions behind search/execute/coordination wrappers) and io-graph (24 behind search/execute) expose action names only; 55 Enceladus actions have no declared argument schema."
    preview_primitive: "Enceladus execute already supports dry_run (whole call or per step) and returns the resolved underlying calls, which is a ready-made preview of the resolved call."
    ```

    ## Acceptance criteria (verbatim from DVP-TSK-816; your only checklist)
    - AC1 A docstore document (subtype doc, keyword research, area schema_form) covers current best practice for generating UI forms from JSON Schema / tool contracts: schema-to-widget mapping, nested objects and arrays, enum and id-reference widgets, client+server validation, dry-run / preview-of-resolved-call patterns, and libraries vs bespoke tradeoffs for React
    - AC2 The document addresses MCP tool schemas specifically, including passthrough wrappers and server-minted identifiers
    - AC3 Documented vs inferred claims are marked; sources cited; candidate canonical API for the kit schema_form package; edges to DVP-PLN-007 and DVP-FTR-098

    ## Research questions (state of the art and the evolution path)
    1. Library landscape 2025-2026: react-jsonschema-form, JSON Forms, uniforms, AutoForm, TanStack Form, React Hook Form with resolvers, Conform; JSON Schema 2020-12 support; Zod 4 JSON Schema interop and the Standard Schema spec. Library vs bespoke for this use.
    2. Schema-to-widget mapping: types and formats, oneOf/anyOf/discriminators, nested objects and arrays, enums, id-reference widgets (typeahead over search for DVP-TSK-*, DOC-*), UI hints via x- extensions.
    3. Validation: client-side (Ajv, lighter validators, or Zod) with the server authoritative; mapping server errors back onto fields; structured error envelopes.
    4. Dry run and execute: rendering the exact resolved call as JSON and as a sentence, diffs, confirm-to-execute, idempotency keys, and server-minted ids (never predict an id; show a placeholder and fill it from the response).
    5. MCP specifics: inputSchema and outputSchema with structured content; elicitation (server-requested, schema-driven user input); tool annotations (readOnlyHint, destructiveHint, idempotentHint) as the source of read/write classification and confirmation UX; unwrapping passthrough wrappers into a per-action schema registry; MCP UI extensions and app SDKs as a trend.
    6. Generative UI (LLM-composed forms) vs deterministic schema forms: where each belongs when the goal is that humans never depend on agent compute.

    ## Research method
    1. Start from the baseline above. If you can reach the Enceladus connector, read the `schema_form` cell in each Wave A audit for detail. Do not re-audit code.
    2. Survey the state of the art with a 2025-2026 source window: specs and RFCs, official docs and release notes, maintainer posts, conference talks, credible engineering write-ups. Date every source; use pre-2024 sources only for foundations.
    3. Give every technique a maturity ring (adopt | trial | assess | hold) with the reason, so emerging trends stay separate from what is production-ready.
    4. Evaluate each stack's gap to the state of the art, then lay out the evolution in three stages: `stage_1_converge` (adopt the best of what the four stacks already have), `stage_2_sota` (uplift beyond it), `stage_3_watch` (emerging, not yet adoptable).
    5. Prefer AWS-native services and open standards. If you recommend a third-party service, name its lock-in and exit cost.
    6. Mark every claim `[DOC]` (backed by a cited source or a Wave A audit) or `[INF]` (your inference). Use fenced YAML blocks, not pipe tables. Aim for 12-25 KB.

    ## Output document (use this skeleton exactly)
    ```
    # DVP-TSK-816 W-B6 Research: schema_form -- current state to state of the art

    **Project**: devops
    **Related**: DVP-TSK-816, DVP-PLN-007, DVP-FTR-098, DOC-5132058DFFAB, DOC-F5EF46453ABB, DOC-04829C0677A3, DOC-3E8F94E6B1E2
    **Author**: claude.ai research agent <your ENC-SES id>, <model>
    **Created**: <today's date>

    ## 0. Scope, method and source window
    ## 1. Current state across stacks (baseline)
    ## 2. State of the art, 2025-2026 (per technique: what, why now, maturity ring, sources)
    ## 3. Gap evaluation per stack (YAML: stack -> {current, sota_target, gap, effort: S|M|L, risk})
    ## 4. Evolution path (YAML: stage_1_converge, stage_2_sota, stage_3_watch)
    ## 5. Candidate canonical API for @io-kit/schema_form (TypeScript signatures and data contracts)
    ## 6. MCP contract handling (passthrough wrappers, missing schemas, server-minted ids)
    ## 7. Open decisions for io
    ## Inference register
    ## Sources (title, publisher, date, URL)
    ```
    Section 5 starting point, to refine or replace: `<SchemaForm contract onDryRun onExecute />, resolveCall(contract, values), ActionRegistry.unwrap(surface)`.

    ## Delivery (Enceladus governance; task DVP-TSK-816 is your only checklist)
    Run these steps once the document is final. If your research mode cannot call tools, end your reply with the complete document in one markdown block followed by the line `READY TO PUBLISH`; when io replies "publish", run the steps then.
    1. `connection_health` -> governance_hash. Pass it on every write.
    2. `coordination` agent.type.list -> pick the claude.ai-webui type for your model (Sonnet 5 = ENC-AGT-00D). Then agent.register `{agent_type_id, runtime: "claude_ai_webui", project_id: "devops"}` and agent.claim `{session_id}`. Keep session_id and sci. Every write needs sci; checkout, advance and worklog also need provider = your session_id. `advance_task_status` takes sci and provider, not active_agent_session_id.
    3. `tracker_get DVP-TSK-816`. If components is empty, `tracker_set` components = ["comp-devops-governance"]. Then `checkout_task DVP-TSK-816`.
    4. `documents_put` `{project_id: "devops", document_subtype: "doc", title, content, keywords: ["research", "schema-form", "state-of-the-art", "convergence", "dvp-pln-007"], related_items: [every id on the Related line], governance_hash}`. Keep the returned DOC id.
    5. For each acceptance criterion (criterion_index 0..2): `tracker_set_acceptance_evidence` `{record_id: "DVP-TSK-816", criterion_index, evidence: "<DOC id> section <n>: <one-line fact>", evidence_acceptance: true, governance_hash, provider}`. Stamp only what the document satisfies; otherwise fix the document first (`documents_patch` with the full content).
    6. `advance_task_status DVP-TSK-816` -> `coding-complete` with transition_evidence `{documentation_evidence: [DOC id]}`, then -> `closed` with transition_evidence `{no_code_evidence: "<what you produced and how you checked it>", documentation_evidence: [DOC id]}`.
    7. `append_worklog DVP-TSK-816` "[END] <DOC id>: <three-line summary>" (needs governance_hash, provider, sci), then `coordination` agent.retire `{session_id}`.
    Do not modify DVP-PLN-007 or any other record. Never paste credentials or tokens anywhere.

    Final reply to io: the DOC id, the task status, and your top five recommendations, one line each.

## W-B7 recipes (DVP-TSK-817)

    # W-B7 research: recipes -- DVP-TSK-817 (DVP-PLN-007 Wave B)
    Recommended setup: Claude Sonnet 5, Research (Advanced) on, Enceladus connector enabled.

    You are a research agent for io's Enceladus program. Define the baseline for a state-of-the-art recipes package: saved, versioned, human-operable workflows of governed execute steps, with bindings and human gates, so a person can run what an agent would otherwise plan. No stack has this, so your research sets the baseline.

    ## Program context (ground truth as of 2026-10-10)
    ```yaml
    program: DVP-FTR-098 cross-stack UI convergence (idea DOC-5132058DFFAB, plan DVP-PLN-007)
    north_star: every action an agent can execute through an MCP surface is executable by a human in that stack's UI (parity diff = capability registry vs UI route manifest, enforced in CI)
    delivery_model: one versioned kit package per design area (auth, shell, md, search, feed, schema_form, recipes, gates); each stack pins a version; an improvement ships as a kit bump plus one PR per stack. Package home and naming are undecided, so write it as @io-kit/<area>.
    stacks:
      enceladus.jreese.net: React + Vite + Tailwind 4 + TanStack Query (frontend/ui-v2); AWS Cognito, Lambda, API Gateway, CloudFront, AppSync Events, DynamoDB
      ai.vagamod.io: Next.js app router + next-auth v5 (Keycloak OIDC) + Tailwind 3 + TanStack Query/Table; SST on AWS
      think.thepup.io: React + Vite (JS), react-router 6, vite-plugin-pwa; fronts the io-graph MCP surface
      coach.thepup.io: React + Vite (JS); carries the newest feed, auth-boundary and caching decisions
    constraints: iOS home-screen PWA is a first-class target; AWS-native backends; stacks deploy independently; agents and humans call the same governed HTTP handlers (MCP is a serialization adapter over them)
    wave_a_audits: {enceladus: DOC-AEF68227FEBB, vagamod: DOC-85B6774DAC96, think: DOC-90930433E582, coach: DOC-7789FF132F90, mcp_capability_inventory: DOC-04829C0677A3, ledger: DOC-F5EF46453ABB}
    ```

    ## Current state of recipes (Wave A audits, snapshots at origin/main 2026-10-08)
    ```yaml
    all_stacks: "nothing. Nearest analogues: vagamod bulk-import jobs with polling; coach's presign -> upload -> commit attachment sequence; Enceladus lifecycle arcs (checkout -> advance -> evidence -> close), which today exist only as prose in agent skills."
    execute_contract: "Enceladus execute takes steps[{action, arguments, dry_run?, on_error: abort|continue}] plus a top-level dry_run, and returns per-step status with the resolved underlying calls; each step carries governance_hash inside its arguments."
    prior_spec: "DOC-3E8F94E6B1E2 section 3: recipe = {name, version, steps[]}; step = {action, arguments with bindings, on_error} or {gate: human, prompt, inputs[], resume_condition}; bindings are $N.path dotted references to earlier step results, deliberately not expressions; interactions are Dry run all, Run to next gate, Resume. Open: storage, versioning, binding scope."
    ```

    ## Acceptance criteria (verbatim from DVP-TSK-817; your only checklist)
    - AC1 A docstore document (subtype doc, keyword research, area recipes) covers current best practice for human-operable workflow runners: ordered step definitions, inter-step bindings (dotted-path only vs expression languages), human-in-the-loop gates, resumability, dry-run of whole workflows, versioning and storage of workflow definitions
    - AC2 The document evaluates at least three existing approaches (e.g. declarative workflow DSLs, step-function style state machines, notebook-style runners) against the Enceladus execute step contract
    - AC3 Documented vs inferred claims are marked; sources cited; candidate canonical API for the kit recipes package; edges to DVP-PLN-007 and DVP-FTR-098

    ## Research questions (state of the art and the evolution path)
    1. Evaluate at least three approaches against the execute contract: declarative workflow specs (Arazzo 1.0, CNCF Serverless Workflow, GitHub Actions/Argo YAML); state machines (AWS Step Functions ASL with JSONata, XState v5); durable-execution engines (Temporal, Restate, Inngest, and any AWS-native durable option); notebook and runbook runners (Jupyter, Runme and similar).
    2. Bindings: dotted paths vs JSON Pointer (RFC 6901) vs JSONPath (RFC 9535) vs JSONata vs CEL vs Arazzo runtime expressions; predictability and security; static validation of a binding against an output schema.
    3. Human-in-the-loop gates: Step Functions task tokens, Temporal signals, GitHub environment approvals, agent-framework interrupts (e.g. LangGraph); resuming with gate inputs such as a PR URL.
    4. Resumability and failure: checkpointed run state, replay, per-step idempotency, partial failure and compensation (saga).
    5. Dry-running a whole workflow when later steps depend on earlier results: placeholder vs mocked bindings, plan/apply models.
    6. Versioning and storage: definitions as docstore documents vs tracker records vs governance files; semver and migration of in-flight runs. Recommend where Enceladus recipes should live (DOC-3E8F94E6B1E2 grooming item 2).

    ## Research method
    1. Start from the baseline above. If you can reach the Enceladus connector, read the `recipes` cell in each Wave A audit for detail. Do not re-audit code.
    2. Survey the state of the art with a 2025-2026 source window: specs and RFCs, official docs and release notes, maintainer posts, conference talks, credible engineering write-ups. Date every source; use pre-2024 sources only for foundations.
    3. Give every technique a maturity ring (adopt | trial | assess | hold) with the reason, so emerging trends stay separate from what is production-ready.
    4. Evaluate each stack's gap to the state of the art, then lay out the evolution in three stages: `stage_1_converge` (adopt the best of what the four stacks already have), `stage_2_sota` (uplift beyond it), `stage_3_watch` (emerging, not yet adoptable).
    5. Prefer AWS-native services and open standards. If you recommend a third-party service, name its lock-in and exit cost.
    6. Mark every claim `[DOC]` (backed by a cited source or a Wave A audit) or `[INF]` (your inference). Use fenced YAML blocks, not pipe tables. Aim for 12-25 KB.

    ## Output document (use this skeleton exactly)
    ```
    # DVP-TSK-817 W-B7 Research: recipes -- current state to state of the art

    **Project**: devops
    **Related**: DVP-TSK-817, DVP-PLN-007, DVP-FTR-098, DOC-5132058DFFAB, DOC-F5EF46453ABB, DOC-3E8F94E6B1E2
    **Author**: claude.ai research agent <your ENC-SES id>, <model>
    **Created**: <today's date>

    ## 0. Scope, method and source window
    ## 1. Current state across stacks (baseline)
    ## 2. State of the art, 2025-2026 (per technique: what, why now, maturity ring, sources)
    ## 3. Gap evaluation per stack (YAML: stack -> {current, sota_target, gap, effort: S|M|L, risk})
    ## 4. Evolution path (YAML: stage_1_converge, stage_2_sota, stage_3_watch)
    ## 5. Candidate canonical API for @io-kit/recipes (TypeScript signatures and data contracts)
    ## 6. Approach evaluation against the execute contract (at least three approaches, YAML scorecard)
    ## 7. Binding grammar recommendation
    ## 8. Open decisions for io
    ## Inference register
    ## Sources (title, publisher, date, URL)
    ```
    Section 5 starting point, to refine or replace: `defineRecipe({name, version, steps}), runRecipe(recipe, {mode: 'dry_run' | 'to_next_gate'}), resume(runId, gateInputs)`.

    ## Delivery (Enceladus governance; task DVP-TSK-817 is your only checklist)
    Run these steps once the document is final. If your research mode cannot call tools, end your reply with the complete document in one markdown block followed by the line `READY TO PUBLISH`; when io replies "publish", run the steps then.
    1. `connection_health` -> governance_hash. Pass it on every write.
    2. `coordination` agent.type.list -> pick the claude.ai-webui type for your model (Sonnet 5 = ENC-AGT-00D). Then agent.register `{agent_type_id, runtime: "claude_ai_webui", project_id: "devops"}` and agent.claim `{session_id}`. Keep session_id and sci. Every write needs sci; checkout, advance and worklog also need provider = your session_id. `advance_task_status` takes sci and provider, not active_agent_session_id.
    3. `tracker_get DVP-TSK-817`. If components is empty, `tracker_set` components = ["comp-devops-governance"]. Then `checkout_task DVP-TSK-817`.
    4. `documents_put` `{project_id: "devops", document_subtype: "doc", title, content, keywords: ["research", "recipes", "state-of-the-art", "convergence", "dvp-pln-007"], related_items: [every id on the Related line], governance_hash}`. Keep the returned DOC id.
    5. For each acceptance criterion (criterion_index 0..2): `tracker_set_acceptance_evidence` `{record_id: "DVP-TSK-817", criterion_index, evidence: "<DOC id> section <n>: <one-line fact>", evidence_acceptance: true, governance_hash, provider}`. Stamp only what the document satisfies; otherwise fix the document first (`documents_patch` with the full content).
    6. `advance_task_status DVP-TSK-817` -> `coding-complete` with transition_evidence `{documentation_evidence: [DOC id]}`, then -> `closed` with transition_evidence `{no_code_evidence: "<what you produced and how you checked it>", documentation_evidence: [DOC id]}`.
    7. `append_worklog DVP-TSK-817` "[END] <DOC id>: <three-line summary>" (needs governance_hash, provider, sci), then `coordination` agent.retire `{session_id}`.
    Do not modify DVP-PLN-007 or any other record. Never paste credentials or tokens anywhere.

    Final reply to io: the DOC id, the task status, and your top five recommendations, one line each.

## W-B8 gates (DVP-TSK-818)

    # W-B8 research: gates -- DVP-TSK-818 (DVP-PLN-007 Wave B)
    Recommended setup: Claude Sonnet 5, Research (Advanced) on, Enceladus connector enabled.

    You are a research agent for io's Enceladus program. Define the baseline for a state-of-the-art gates package: one decision inbox for every decision the system cannot make alone, where each card shows the exact call that fires on approve. Enceladus has a partial escalation cockpit and nothing else exists, so your research sets the baseline and the taxonomy.

    ## Program context (ground truth as of 2026-10-10)
    ```yaml
    program: DVP-FTR-098 cross-stack UI convergence (idea DOC-5132058DFFAB, plan DVP-PLN-007)
    north_star: every action an agent can execute through an MCP surface is executable by a human in that stack's UI (parity diff = capability registry vs UI route manifest, enforced in CI)
    delivery_model: one versioned kit package per design area (auth, shell, md, search, feed, schema_form, recipes, gates); each stack pins a version; an improvement ships as a kit bump plus one PR per stack. Package home and naming are undecided, so write it as @io-kit/<area>.
    stacks:
      enceladus.jreese.net: React + Vite + Tailwind 4 + TanStack Query (frontend/ui-v2); AWS Cognito, Lambda, API Gateway, CloudFront, AppSync Events, DynamoDB
      ai.vagamod.io: Next.js app router + next-auth v5 (Keycloak OIDC) + Tailwind 3 + TanStack Query/Table; SST on AWS
      think.thepup.io: React + Vite (JS), react-router 6, vite-plugin-pwa; fronts the io-graph MCP surface
      coach.thepup.io: React + Vite (JS); carries the newest feed, auth-boundary and caching decisions
    constraints: iOS home-screen PWA is a first-class target; AWS-native backends; stacks deploy independently; agents and humans call the same governed HTTP handlers (MCP is a serialization adapter over them)
    wave_a_audits: {enceladus: DOC-AEF68227FEBB, vagamod: DOC-85B6774DAC96, think: DOC-90930433E582, coach: DOC-7789FF132F90, mcp_capability_inventory: DOC-04829C0677A3, ledger: DOC-F5EF46453ABB}
    ```

    ## Current state of gates (Wave A audits, snapshots at origin/main 2026-10-08)
    ```yaml
    enceladus: "partial. io approval cockpit for escalations (ENC-FTR-121: escalation.request -> ESC record -> io decides): pending vs terminal split, a freshly rendered diff with a drift flag per escalation, approve/deny with an optional guidance note; Home 'Requires io' queue (paused approvals, stale locks, escalations); the server decision needs a Cognito session, an interactive-human ID token and an email allow-list. No acceptance-evidence or reconciliation cards; the exact call that fires is not shown. Open ENC-ISS-773: the queue renders only the enceladus project."
    think: "no inbox. Nearest analogue: the /concepts review queue (accept, rename, merge, split, kill)."
    vagamod: "none."
    coach: "none."
    prior_spec: "DOC-3E8F94E6B1E2 section 3.5: card types are acceptance (checklist from verification_criteria), reconciliation (rule-generated candidates, io picks) and drift (telemetry only, no proposed action); each card shows the exact call(s) that fire on Clear. Open: taxonomy, what counts as 'the system does not know why' vs rule-resolvable, expiry."
    ```

    ## Acceptance criteria (verbatim from DVP-TSK-818; your only checklist)
    - AC1 A docstore document (subtype doc, keyword research, area gates) covers current best practice for decision inboxes / approval queues: card taxonomies (acceptance, reconciliation, drift/telemetry-only), showing the exact action that fires on approve, expiry and escalation, audit trail, and mobile-first approval UX
    - AC2 The document proposes a gate taxonomy and the rule for when a gate carries a proposed action vs telemetry only (carried from DOC-3E8F94E6B1E2 section 4)
    - AC3 Documented vs inferred claims are marked; sources cited; candidate canonical API for the kit gates package; edges to DVP-PLN-007 and DVP-FTR-098

    ## Research questions (state of the art and the evolution path)
    1. Decision-inbox and approval UX in 2025-2026: code-review and deployment approvals, issue-tracker triage inboxes, chat-ops approvals, incident acknowledgement, cloud pipeline manual approvals, and the emerging 'agent inbox' and tool-call confirmation patterns for human-in-the-loop AI.
    2. Taxonomy: acceptance, reconciliation, drift/telemetry-only, FSM escalation, and anything else the research turns up (budget or limit breaches, security). The rule for when a card carries a proposed action vs telemetry only.
    3. Showing exactly what fires: resolved call, diff and blast radius; risk levels; tool annotations (destructiveHint); stale-state protection on approve (If-Match / optimistic concurrency).
    4. Lifecycle: expiry and SLAs, escalation chains, delegation, snooze, batch approve.
    5. Audit: who, when, what and why; linkage to record history; tamper evidence; step-up re-authentication (passkeys/WebAuthn) for high-risk approvals.
    6. Mobile-first approval: Web Push for iOS home-screen PWAs, one-tap approve with step-up, swipe actions, offline queues.

    ## Research method
    1. Start from the baseline above. If you can reach the Enceladus connector, read the `gates` cell in each Wave A audit for detail. Do not re-audit code.
    2. Survey the state of the art with a 2025-2026 source window: specs and RFCs, official docs and release notes, maintainer posts, conference talks, credible engineering write-ups. Date every source; use pre-2024 sources only for foundations.
    3. Give every technique a maturity ring (adopt | trial | assess | hold) with the reason, so emerging trends stay separate from what is production-ready.
    4. Evaluate each stack's gap to the state of the art, then lay out the evolution in three stages: `stage_1_converge` (adopt the best of what the four stacks already have), `stage_2_sota` (uplift beyond it), `stage_3_watch` (emerging, not yet adoptable).
    5. Prefer AWS-native services and open standards. If you recommend a third-party service, name its lock-in and exit cost.
    6. Mark every claim `[DOC]` (backed by a cited source or a Wave A audit) or `[INF]` (your inference). Use fenced YAML blocks, not pipe tables. Aim for 12-25 KB.

    ## Output document (use this skeleton exactly)
    ```
    # DVP-TSK-818 W-B8 Research: gates -- current state to state of the art

    **Project**: devops
    **Related**: DVP-TSK-818, DVP-PLN-007, DVP-FTR-098, DOC-5132058DFFAB, DOC-F5EF46453ABB, DOC-3E8F94E6B1E2
    **Author**: claude.ai research agent <your ENC-SES id>, <model>
    **Created**: <today's date>

    ## 0. Scope, method and source window
    ## 1. Current state across stacks (baseline)
    ## 2. State of the art, 2025-2026 (per technique: what, why now, maturity ring, sources)
    ## 3. Gap evaluation per stack (YAML: stack -> {current, sota_target, gap, effort: S|M|L, risk})
    ## 4. Evolution path (YAML: stage_1_converge, stage_2_sota, stage_3_watch)
    ## 5. Candidate canonical API for @io-kit/gates (TypeScript signatures and data contracts)
    ## 6. Gate taxonomy and the proposed-action vs telemetry-only rule (AC2)
    ## 7. Card contract (fields every card carries)
    ## 8. Open decisions for io
    ## Inference register
    ## Sources (title, publisher, date, URL)
    ```
    Section 5 starting point, to refine or replace: `<GateInbox sources />, GateCard { kind, proposedCall?, evidence, expiresAt }, decide(cardId, verdict, {ifMatch})`.

    ## Delivery (Enceladus governance; task DVP-TSK-818 is your only checklist)
    Run these steps once the document is final. If your research mode cannot call tools, end your reply with the complete document in one markdown block followed by the line `READY TO PUBLISH`; when io replies "publish", run the steps then.
    1. `connection_health` -> governance_hash. Pass it on every write.
    2. `coordination` agent.type.list -> pick the claude.ai-webui type for your model (Sonnet 5 = ENC-AGT-00D). Then agent.register `{agent_type_id, runtime: "claude_ai_webui", project_id: "devops"}` and agent.claim `{session_id}`. Keep session_id and sci. Every write needs sci; checkout, advance and worklog also need provider = your session_id. `advance_task_status` takes sci and provider, not active_agent_session_id.
    3. `tracker_get DVP-TSK-818`. If components is empty, `tracker_set` components = ["comp-devops-governance"]. Then `checkout_task DVP-TSK-818`.
    4. `documents_put` `{project_id: "devops", document_subtype: "doc", title, content, keywords: ["research", "gates", "state-of-the-art", "convergence", "dvp-pln-007"], related_items: [every id on the Related line], governance_hash}`. Keep the returned DOC id.
    5. For each acceptance criterion (criterion_index 0..2): `tracker_set_acceptance_evidence` `{record_id: "DVP-TSK-818", criterion_index, evidence: "<DOC id> section <n>: <one-line fact>", evidence_acceptance: true, governance_hash, provider}`. Stamp only what the document satisfies; otherwise fix the document first (`documents_patch` with the full content).
    6. `advance_task_status DVP-TSK-818` -> `coding-complete` with transition_evidence `{documentation_evidence: [DOC id]}`, then -> `closed` with transition_evidence `{no_code_evidence: "<what you produced and how you checked it>", documentation_evidence: [DOC id]}`.
    7. `append_worklog DVP-TSK-818` "[END] <DOC id>: <three-line summary>" (needs governance_hash, provider, sci), then `coordination` agent.retire `{session_id}`.
    Do not modify DVP-PLN-007 or any other record. Never paste credentials or tokens anywhere.

    Final reply to io: the DOC id, the task status, and your top five recommendations, one line each.
