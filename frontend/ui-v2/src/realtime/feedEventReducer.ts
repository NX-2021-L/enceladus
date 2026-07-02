import type { FeedRealtimeEvent, FeedSnapshot } from '../types/feedEvents'

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
