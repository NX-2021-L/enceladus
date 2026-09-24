import type { FeedRealtimeEvent, FeedSnapshot } from '../types/feedEvents'

/**
 * DECISION (ENC-TSK-K24 / B67 AC-12): the normalized entity layer IS the
 * TanStack Query per-key cache — no TanStack DB, no Zustand+Immer normalized
 * store.
 *
 * Every Enceladus record is already cached by (type, projectId, id) via
 * `recordKeys.detail(...)` (src/api/queryOptions.ts) — records reference
 * each other by ID (a Plan's `objectives_set: string[]`), never by
 * embedding. That is exactly the normalization TanStack DB's collections or
 * a hand-rolled Zustand+Immer store would exist to provide. Measured,
 * gamma-verified evidence that the existing cache already delivers
 * "single mutation propagates to all referencing views without per-view
 * cache code" (AC-12's own bar):
 *   - ENC-TSK-K23 (useRecordMutation.test.tsx): two independent React
 *     components subscribed to the same `recordKeys.detail(...)` key
 *     (standing in for a task detail page and its parent plan page) each
 *     re-rendered EXACTLY ONCE per mutation from ONE `setQueryData` call —
 *     zero cascading renders, zero per-view propagation code.
 *   - ENC-TSK-K24 (RealtimeFeedProvider.test.tsx): `mergeBufferedEvents()`
 *     propagates N buffered realtime events into every consumer of the
 *     shared `events` context value in a single state update.
 *
 * Rejected alternatives:
 *   - TanStack DB v0.6: would require converting every one of the six
 *     record-type `queryOptions` factories into differential-dataflow
 *     collections, a new dependency + bundle cost + team learning curve, to
 *     re-derive a propagation guarantee this codebase's ID-referencing data
 *     shape already gets from TanStack Query's own cache-key identity.
 *   - Zustand + Immer normalized store: would duplicate what TanStack Query
 *     already owns (cache, staleness, request dedup, invalidation, the
 *     onMutate/onError snapshot-rollback contract K23 depends on) in a
 *     second, hand-rolled state layer, and would still need bridging back
 *     into TanStack Query for network/loading state — strictly more moving
 *     parts for no additional guarantee.
 *
 * Full write-up with the measured numbers: ENC-TSK-K24 task worklog.
 */
export const REALTIME_FEED_QUERY_KEY = ['realtime-feed'] as const

export function mergeFeedEvents(
  existing: FeedRealtimeEvent[],
  incoming: FeedRealtimeEvent[],
): FeedRealtimeEvent[] {
  const byId = new Map<string, FeedRealtimeEvent>()
  for (const event of existing) byId.set(event.eventId, event)
  for (const event of incoming) byId.set(event.eventId, event)
  return Array.from(byId.values()).sort((a, b) => b.cursor - a.cursor)
}

export function snapshotToFeedState(snapshot: FeedSnapshot): FeedRealtimeEvent[] {
  return [...snapshot.events].sort((a, b) => b.cursor - a.cursor)
}

export function filterFeedEvents(
  events: FeedRealtimeEvent[],
  recordTypes: string[],
): FeedRealtimeEvent[] {
  if (recordTypes.length === 0) return events
  const allowed = new Set(recordTypes)
  return events.filter((event) => allowed.has(event.record_type))
}

export function maxCursor(events: FeedRealtimeEvent[]): number {
  return events.reduce((max, event) => Math.max(max, event.cursor), 0)
}
