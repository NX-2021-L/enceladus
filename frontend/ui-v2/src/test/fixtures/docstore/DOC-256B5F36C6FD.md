# DOC-256B5F36C6FD W-C5 Reconcile: feed (DVP-TSK-823)

**Project**: devops
**Related**: DVP-TSK-823, DVP-PLN-007, DVP-FTR-098, DOC-AEF68227FEBB, DOC-85B6774DAC96, DOC-90930433E582, DOC-7789FF132F90, DOC-A4F0A2A44AE2, DOC-A5BCD6216666, DOC-5132058DFFAB
**Author**: DVP-TSK-823 subagent of ENC-SES-0IT (claude sonnet)
**Created**: 2026-10-10

Bottom line: the kit should be coach's wire contract (signal-then-fetch, opaque keyset cursor, window cap) running on enceladus's client engine (virtualization, IndexedDB, reconnect and gap handling), with think's sentinel and cursor-reset guard, realtime kept on AppSync Events (not the API Gateway WebSocket default of DOC-A5BCD6216666) with Cognito/OIDC auth. `since` is made optional so coach can adopt before it grows a seq. [INF]

## 0. Scope and inputs

```yaml
inputs:
  DOC-AEF68227FEBB: enceladus audit, feed cell (present: yes)
  DOC-85B6774DAC96: vagamod audit, feed cell (present: no)
  DOC-90930433E582: think audit, feed cell (present: yes, no realtime)
  DOC-7789FF132F90: coach audit, feed cell (present: yes, newest reference)
  DOC-A4F0A2A44AE2: W-B5 research (DVP-TSK-815): candidate @io-kit/feed API, stages, D1-D6
  DOC-A5BCD6216666: settled reference pattern for infinite-scroll feeds (read here only through W-B5 section 6 [DOC])
  DOC-5132058DFFAB: matrix cell field definitions (cited by the brief; not in the pack)
not_available:
  - DOC-A5BCD6216666 full text: W-B5 section 6 is its summary of it, and W-B5 states it read the source directly. Every claim about A5BCD in this doc is via that summary.
  - DOC-5132058DFFAB and DOC-F5EF46453ABB (coach-vs-A5BCD divergence ledger): not in pack.
  - Source code of all four stacks: only audit cells; no latency or p95 measurements exist for any stack.
```

## 1. Area-by-stack matrix

Weighting: coach (DOC-7789FF132F90) is the newest reference and sets the wire contract and trigger/transport behavior. Enceladus is weighed honestly against it: its client engine is richer in the three areas that matter on a phone over a long session (virtualization, IndexedDB persistence, reconnect and gap handling), and its delta contract has a seq that coach lacks. Coach is the newer, cleaner contract; enceladus is the more complete engine. [INF]

```yaml
enceladus:
  present: true
  source: DOC-AEF68227FEBB
  implementation: "FeedRoute.tsx, sync/cacheEngine.ts, sync/deltaHeal.ts, realtime/RealtimeFeedProvider.tsx + appsyncRealtimeClient.ts, store/feedBufferStore.ts, components/VirtualList.tsx; backend feed_query + appsync_feed_publisher + feed_publisher lambdas"
  libraries: ["@tanstack/react-virtual 3.14", "@tanstack/react-query 5.101", "zustand 5.0", "AppSync Events WebSocket"]
  patterns:
    - cursor-paginated corpus warm start
    - delta feed by since-seq with doc-seq cursor
    - zustand insert buffer
    - virtualized list with scroll restore
    - reconnect backoff 500ms-30s with gap_too_large signal and liveness watchdog
    - IndexedDB cache engine with stale notice
  quality_signals: "tests: realtime 5 files, sync 8, feedBufferStore, VirtualList, feeds.test.ts (15+); per-event latencyMs recorded; AppSync keepalive ~60s median on gamma; no p95; ENC-ISS-711/718/731 closed"
  weaknesses: "AppSync API key in public client config (WS auth path, open ENC-ISS-546); zustand buffer duplicates a cache next to Query; no cursor signing stated [DOC for key, INF for rest]"
vagamod:
  present: false
  source: DOC-85B6774DAC96
  implementation: "dashboard/page.tsx (count summary); components/bulk/data-table.tsx (react-table + react-virtual ^3.13.21)"
  patterns: ["virtualized tables", "paginated fetch of all objects into client cache"]
  quality_signals: "no tests, no realtime (no EventSource or WebSocket found)"
  weaknesses: "no card feed, keyset cursor UI or insert buffer [DOC]; consumer of the kit only if a feed surface appears [INF]"
think:
  present: true
  source: DOC-90930433E582
  implementation: "views/TimelineView.jsx, lib/timelinePager.js, timelineViewCache.js, timelineShape.js, hooks/useSourceFacets.js"
  libraries: []
  patterns:
    - "cursor pages of 20, append-only, no full refetch"
    - "IntersectionObserver sentinel rootMargin 400px"
    - "sort toggle with cursor-reset guard"
    - "per-view cache and scroll/drawer reopen hint in sessionStorage"
    - "since/until range params"
  quality_signals: "three verify-* scripts (pager 259, shape 82, view cache 109 lines); first paint exactly 20 rows by design; open INT-ISS-037 (since/until routing)"
  weaknesses: "no realtime, no insert buffer, no virtualization, no types (JS) [DOC]"
coach:
  present: true
  source: DOC-7789FF132F90
  weight: newest reference
  implementation: "views/TimelinePage.jsx, lib/timelineWindows.js (pure window engine), lib/useWindowSentinel.js, lib/eventsApi.js, components/NewActivityBanner.jsx, realtime/RealtimeProvider.jsx + appsyncEventsClient.js, backend coach_events lambda (GET /events)"
  libraries: []
  patterns:
    - "GET /events count mode (limit/before, default 50) and window mode (window_start/window_end/cursor, WINDOW_CAP 200, next_cursor)"
    - "opaque keyset cursor base64url(sk) unpadded, validated to fall inside the requested window; DynamoDB single table, ULID sort keys, no GSI"
    - "time-windowed loading: head window 14 local days, then 7-day windows, empty weeks skipped via newest-older instant, local-midnight boundaries with DST-safe arithmetic"
    - "sentinel rooted on scroll container, 150% bottom margin, rearm key; load error pauses autoload until Retry or online"
    - "signal-then-fetch over AppSync Events: frame counts a banner and prefetches head into a HELD payload applied on user Show; own-write echo dropped by sk; no client ka frames, server connectionTimeoutMs sweep; transport badge SNAPSHOT when no realtime host baked in"
  quality_signals: "13 client test groups (timelineWindows, realtimeProvider, appsyncEventsClient, transportStatus, payloadOrder, backfill, ...) plus backend test_window_events, test_sk_collision; latency not measured; no open feed ISS"
  weaknesses: "no TanStack Query, no virtualization, no IndexedDB, unsigned cursors, no seq or tombstones, no bidirectional since (live head refetch instead) [DOC]"
```

## 2. Best-of-breed

```yaml
winner: composite, anchored on coach for contract and enceladus for engine
by_concern:
  wire_contract_and_realtime_semantics:
    winner: coach
    reasons:
      - newest, in production, and already the outline of DOC-A5BCD6216666 (keyset cursors, sentinel, newer-items pill) [DOC: DOC-7789FF132F90]
      - signal-then-fetch keeps item payloads on the governed HTTP handler, which DVP-FTR-098 requires [DOC: DOC-A4F0A2A44AE2 s4 via INF I2]
      - held-payload applied on Show means no reflow under the reader [DOC]
  client_engine:
    winner: enceladus
    reasons:
      - only stack with virtualization, IndexedDB persistence, scroll restore, reconnect backoff with jitter range, gap_too_large and a liveness watchdog [DOC: DOC-AEF68227FEBB]
      - its seq-based delta is the only gap-detectable contract of the four [INF]
    honest_caveat: "its zustand buffer and API-key auth are the parts NOT to carry over; the kit replaces them with a core buffer on Query and Cognito/OIDC"
  trigger_and_filter_handling:
    winner: think
    reasons: ["smallest sentinel plus cursor-reset guard on sort change [DOC: DOC-90930433E582]", "guard moves server-side via the filter hash in the cursor"]
  time_windowed_loading:
    winner: coach
    reasons: ["unique to coach: bounded windows, empty-week skipping, DST-safe local-midnight boundaries [DOC]", "kept as an optional pure helper (@io-kit/feed/windows), not part of the core contract [INF]"]
contributions:
  enceladus: [core state machine (gap, watchdog, backoff), IndexedDB persister, virtualizer integration, scroll restore]
  coach: [page and signal wire shape, held-payload pill, own-write echo drop, window helper, transport badge incl. SNAPSHOT kill switch, test suites as conformance seeds]
  think: [sentinel defaults, cursor-reset guard, verify-script style pager tests]
  vagamod: [none for the feed; virtualized table stays its table concern; consumer only if a feed surface exists]
tension_resolved:
  - "coach has no virtualization: virtualize above a threshold, content-visibility below (A5BCD via W-B5 s6, heuristic thresholds measured per D5)"
  - "coach has no seq: since() is optional; without it the core refetches the head page on signal (coach's current behavior), with it the core gets gap detection (enceladus's behavior)"
  - "A5BCD says rootMargin 150% bottom; think uses 400px; coach uses 150%: kit default 150% (settled reference and coach agree), 400px kept as a configurable value [DOC + INF]"
```

## 3. Canonical kit API

`@io-kit/feed` follows W-B5 section 5 (DOC-A4F0A2A44AE2): headless core, `@io-kit/feed/react`, `@io-kit/feed/appsync`, `@io-kit/feed/testing`, plus an optional `@io-kit/feed/windows`. Departures from W-B5 are listed at the end of this section.

### 3.1 FeedSource data contract

```ts
export type Cursor = string & { __brand: 'Cursor' };     // opaque, HMAC-signed, versioned
export type Seq = number;                                // per-feed, dense, monotonic

export interface PageResponse<T> {
  items: T[];                    // ordered newest first by the ordering key
  next_cursor: Cursor | null;    // older direction
  prev_cursor?: Cursor | null;   // newer direction (bidirectional page params, DOC-A5BCD6216666)
  has_more: boolean;
  head_seq?: Seq;                // present when the feed has a seq
  server_time: string;           // ISO-8601, DOC-A5BCD6216666 envelope
  schema: `feed.v${number}`;
}
export type DeltaOp<T> =
  | { op: 'upsert'; id: string; seq: Seq; item: T }
  | { op: 'delete'; id: string; seq: Seq };
export interface DeltaResponse<T> { ops: DeltaOp<T>[]; head_seq: Seq; gap_too_large?: true; }
export type Signal = { feed: string; seq?: Seq; id?: string; sk?: string };  // never the item
export type TransportStatus = 'connecting' | 'live' | 'stale' | 'reconnecting' | 'offline' | 'snapshot';

export interface FeedSource<T, F = unknown> {
  key(filter: F): readonly unknown[];
  page(a: { filter: F; cursor: Cursor | null; limit: number; direction?: 'older' | 'newer'; signal: AbortSignal }): Promise<PageResponse<T>>;
  since?(a: { filter: F; seq: Seq; signal: AbortSignal }): Promise<DeltaResponse<T>>;   // optional
  subscribe?(a: { filter: F; onSignal(s: Signal): void; onStatus(s: TransportStatus): void }): () => void;
  getId(item: T): string;
  isOwnWrite?(s: Signal): boolean;      // coach: echo dropped by sk
}
```

```yaml
contract:
  page:
    semantics: keyset pagination, never offset; default limit 25, server max 50 (DOC-A5BCD6216666 via W-B5 s6)
    window_mode: optional filter field {window_start, window_end}; server cap 200 per response (coach WINDOW_CAP); next_cursor valid only inside the window
    invalid_cursor: HTTP 400 with code cursor_invalid; client treats as cursor-reset and refetches head
  since:
    semantics: returns ops with seq greater than the argument, in seq order, merged by id with max seq winning; tombstones remove from buffer and cached pages
    absent: when a source omits since, a signal triggers a head-page refetch and dedupe by id (coach behavior); gap detection is then unavailable and gap_row is never shown
    gap: gap_too_large true means drop the buffer and refetch head
  subscribe:
    semantics: optional; absent means no realtime (think, vagamod); transport reports 'snapshot'
    payload: a Signal only; authoritative data always arrives through page or since
cursor_shape:
  wire: base64url(JSON{v:1, k:<last ordering key>, f:<filter hash>, scope, exp, kid}) + "." + base64url(HMAC-SHA256)
  rules:
    - server rejects bad tag, expired, foreign filter hash or foreign scope (HTTP 400)
    - never expose DynamoDB LastEvaluatedKey; k is the ULID/sort key value only
    - kid selects the HMAC key from Secrets Manager (rotation)
    - migration: servers accept coach's unsigned v0 base64url(sk) cursor for one kit minor, then reject
ordering_key:
  display_and_pagination: "(created_at, id) descending, where id is a ULID (coach, DynamoDB sk) or UUIDv7; the sort key is the page cursor's k"
  delta_and_gap_detection: "per-feed dense monotonic seq, assigned by the server (atomic counter in the write transaction, D2 of W-B5)"
  rationale: "ULID/UUIDv7 sorts but cannot reveal a missing item; only a dense seq can [DOC: DOC-A4F0A2A44AE2 I5]. Items without a seq paginate by sort key only."
```

### 3.2 Realtime transport decision

```yaml
decision: AppSync Events, signal-then-fetch, Cognito user-pool auth (enceladus, coach, think) or OIDC (vagamod/Keycloak); publish IAM-only from the governed handler after a successful write
sources:
  - "DOC-A5BCD6216666, as summarized in DOC-A4F0A2A44AE2 s6: default is API Gateway WebSocket (or SSE/polling) pushing {id, sk} or full items"
  - "DOC-A4F0A2A44AE2 s7.3: recommends AppSync Events instead; flagged there as the one deliberate departure (I12, D3)"
agree_with_settled_reference:
  - pending buffer plus N-new pill, dedupe by id, since= catch-up on reconnect, gap row beyond about 2 pages
  - the {id, sk} push variant is exactly a Signal, so signal-then-fetch sits inside the settled default
depart_from_settled_reference:
  what: transport is AppSync Events, not API Gateway WebSocket
  why:
    - "two of four stacks (enceladus, coach) already run AppSync Events in production, so API Gateway WebSocket would be a rewrite in the two stacks that work [DOC: audits]"
    - "API Gateway WebSocket has a 2h connection cap, 10 minute idle timeout and self-managed fan-out; AppSync Events does fan-out (24h cap, ka 60s, connectionTimeoutMs 300000) [DOC: DOC-A4F0A2A44AE2 s2, s7.3]"
    - "an API key in public config lets any holder subscribe to the namespace, so it is dropped in favor of Cognito/OIDC [INF, DOC-A4F0A2A44AE2 I3]"
  status: needs io confirmation (Open decision D1 below)
channels: "/feed/{feedId} shared, /user/{sub}/feed per user; onSubscribe guard calls util.unauthorized() on mismatch"
resilience:
  - reconnect backoff 500ms-30s with jitter (enceladus), resubscribe on every token refresh and before the 24h cap, ka missing for connectionTimeoutMs means dead
  - resume() on visibilitychange visible and pageshow: probe liveness, then since(lastSeq) (or head refetch) before trusting the socket
  - fallback poll every 30-60s while visible when transport is stale or offline
  - build-time kill switch (coach): no realtime host baked in means transport 'snapshot'
```

### 3.3 Core, bindings and config surface

```ts
export function createFeed<T, F>(opts: {
  source: FeedSource<T, F>; queryClient: QueryClient; filter: F;
  pageSize?: number;            // default 25 (settled reference); think passes 20
  maxPages?: number;            // default 10 virtualized, 6 not (settled reference)
  buffer?: 'pill' | 'auto-when-at-top';   // coach default 'pill' with held payload
  persist?: { idb: string; maxAgeMs: number };   // enceladus-style, stale notice
}): Feed<T, F>;                 // Feed = getState, subscribe, loadMore, flushBuffer, refresh, setFilter, resume, dispose
export function FeedList<T>(p: { feed: Feed<T, unknown>; renderCard(item: T, i: number): React.ReactNode;
  estimateSize?: number; virtualizeAbove?: number; sentinelMargin?: string; renderPill?(n: number, flush: () => void): React.ReactNode }): JSX.Element;
```

```yaml
follows_w_b5:
  - package split, createFeed/Feed/useFeed/FeedList signatures, Signal-not-item, tombstones, signed cursors, maxPages, schema feed.vN, appSyncEventsSignals adapter with a JWT auth callback and no API key
departs_from_w_b5:
  - since is optional (W-B5 required it): coach has no seq or tombstones today and think/vagamod have none; making it required would block the two lowest-risk migrations [INF]
  - Signal fields seq, id, sk are optional and PageResponse gains prev_cursor and server_time: reconciles W-B5 with coach (sk in frames, own-write echo) and the DOC-A5BCD6216666 envelope [INF]
  - page() gains a direction argument, and window_start/window_end are filter fields, to carry coach's window mode and A5BCD bidirectional page params [INF]
  - TransportStatus gains 'snapshot' (coach's kill-switch badge) [DOC: DOC-7789FF132F90]
  - default pageSize 25 instead of 20 (settled reference value; think overrides) [DOC + INF]
  - isOwnWrite hook added (coach markOwnWrite) [DOC]
depart_from_settled_reference: [realtime transport, see 3.2]
```

## 4. Migration order

```yaml
- order: 1
  stack: coach.thepup.io
  risk: low-medium
  effort: M
  prerequisite: "kit 0.x published (D1 of W-B5); coach /events adds cursor signing with one-release v0 acceptance; adopt Query, IDB persister and virtualization threshold; keep held-payload pill and window helper; seq and tombstones deferred (since absent)"
  reason: "newest reference and the contract source, so it exercises the contract with the least semantic change; runs the shared conformance suite first"
- order: 2
  stack: enceladus.jreese.net
  risk: medium
  effort: M
  prerequisite: "coach landed; parallel Cognito AppSync namespace live alongside API_KEY (W-B5 D3); core replaces zustand buffer; feed_query implements the signed cursor"
  reason: "richest engine donates to the core, but the auth cutover can drop subscriptions, so it goes after the contract is proven and runs both namespaces for one kit minor"
- order: 3
  stack: think.thepup.io
  risk: low
  effort: S client / M handler
  prerequisite: "kit consumable from JS with d.ts; io-graph handlers gain signed cursor (and since plus seq only if realtime is wanted)"
  reason: "realtime off by default; replaces timelinePager with createFeed; INT-ISS-037 range routing rides along"
- order: 4
  stack: ai.vagamod.io
  risk: low
  effort: S
  prerequisite: "a feed surface exists, decided by the DVP-FTR-098 parity diff; RSC-safe use client boundary; OIDC mode on AppSync Events for Keycloak tokens"
  reason: "no feed today, so it adopts last and only when needed"
```

## 5. Consumer contract tests

All tests live in `@io-kit/feed/testing` and run in each consumer's CI against the real handler. [INF, per brief and W-B5 s7.1]

```yaml
- id: FT-01-page-order
  asserts: pages are newest-first by ordering key, no duplicate or skipped ids across consecutive next_cursor walks, has_more false on the last page
  applies_to: [coach, enceladus, think, vagamod]
- id: FT-02-page-limits
  asserts: default limit and server max honored (25/50 unless overridden); window mode never returns more than 200
  applies_to: [coach, enceladus, think]
- id: FT-03-cursor-signing
  asserts: tampered tag, expired, foreign-filter and foreign-scope cursors return 400 cursor_invalid; LastEvaluatedKey shape never appears; unsigned v0 accepted only inside the migration window
  applies_to: [coach, enceladus, think, vagamod]
- id: FT-04-cursor-reset
  asserts: setFilter discards cursor, buffer and cached pages, and a stale-filter cursor is rejected server-side
  applies_to: [coach, enceladus, think]
- id: FT-05-since-delta
  asserts: since(seq) returns ops in seq order with upsert and delete tombstones; merge by id keeps max seq; deleted ids vanish from buffer and cached pages
  applies_to: [enceladus]   # others once they implement since
- id: FT-06-gap
  asserts: gap_too_large drops the buffer and refetches head; a missing seq in a delta is detected
  applies_to: [enceladus]
- id: FT-07-signal-then-fetch
  asserts: a Signal never carries an item; the pill count increments, the held head payload is applied only on flushBuffer, frames arriving mid-await stay buffered, own-write echo is dropped
  applies_to: [coach, enceladus]
- id: FT-08-no-since-fallback
  asserts: with since absent a signal triggers head refetch and dedupe by id; no gap row is shown
  applies_to: [coach]
- id: FT-09-resume
  asserts: after visibilitychange visible or pageshow, resume() probes liveness and reconciles via since or head refetch before status returns to live
  applies_to: [coach, enceladus]
- id: FT-10-transport-auth
  asserts: subscribe uses a JWT Authorization callback, no API key present in client config; onSubscribe rejects a foreign channel; reconnect and resubscribe on token refresh
  applies_to: [enceladus, coach]
- id: FT-11-snapshot-mode
  asserts: with no subscribe (or no realtime host) transport is 'snapshot', the feed still pages and refreshes
  applies_to: [coach, think, vagamod]
- id: FT-12-schema
  asserts: responses carry schema feed.vN; unknown fields ignored; a vN+1 route can coexist for one kit major
  applies_to: [coach, enceladus, think, vagamod]
- id: FT-13-render-smoke
  asserts: Playwright WebKit smoke for pill, scroll-anchor and resume; virtualization engages above the threshold; no mutation above the viewport during scroll
  applies_to: [coach, enceladus]
```

## 6. Open decisions for io

```yaml
- id: D1
  question: Confirm AppSync Events as the kit realtime transport, departing from the API Gateway WebSocket default in DOC-A5BCD6216666 (the settled doc may need an amendment)
  recommendation: confirm; two of four stacks already run it [INF]
- id: D2
  question: Is since() optional for the kit 0.x (coach adopts without seq) with a required seq by kit 1.0?
  recommendation: yes [INF]
- id: D3
  question: Seq source per backend and package registry (W-B5 D1, D2)
  recommendation: DynamoDB atomic counter in the write transaction; CodeArtifact [DOC: DOC-A4F0A2A44AE2]
- id: D4
  question: Does coach's time-window loading become a first-class kit helper or remain coach-local?
  recommendation: kit helper at @io-kit/feed/windows, optional [INF]
- id: D5
  question: Virtualization thresholds (150 cards, maxPages x pageSize over 200) are unmeasured heuristics
  recommendation: measure on the oldest supported iPhone PWA before freezing [DOC: W-B5 D5]
- id: D6
  question: Does vagamod need a feed at all
  recommendation: let the DVP-FTR-098 parity diff decide [DOC: W-B5 D6]
```

Edges: implements DVP-PLN-007 Wave C item W-C5 via DVP-TSK-823; serves DVP-FTR-098 by keeping every feed read on the governed HTTP handlers (page and since) that MCP adapts, with realtime carrying signals only. Builds on every input: DOC-AEF68227FEBB, DOC-85B6774DAC96, DOC-90930433E582, DOC-7789FF132F90 (matrix, section 1), DOC-A4F0A2A44AE2 (API base, section 3) and DOC-A5BCD6216666 (settled defaults, via W-B5 section 6). Matrix cell format per DOC-5132058DFFAB. [INF]

## Inference register

```yaml
- C1: the composite best-of-breed split (coach contract, enceladus engine, think trigger) is a judgment, not measured; no stack has latency data
- C2: making since optional is a departure from W-B5 chosen to unblock coach and think; seq becomes required by kit 1.0
- C3: Signal fields seq, id, sk optional so coach frames fit without a backend change
- C4: pageSize default 25 and sentinel margin 150% follow the settled reference; think's 20 and 400px stay as overrides
- C5: all claims about DOC-A5BCD6216666 come from W-B5 section 6; the full text was not in the pack
- C6: DOC-5132058DFFAB and DOC-F5EF46453ABB were not in the pack; the matrix fields follow the brief
- C7: migration order (coach first) reflects lowest semantic change to the contract source, not lowest absolute effort (think is smaller); risk ratings are estimates
- C8: weaknesses listed for stacks beyond the audits' own words (zustand duplicate cache, no cursor signing in enceladus) are inferred
- C9: contract test applicability lists assume seq and tombstones exist only in enceladus today
```
