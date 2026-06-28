/**
 * Live-feed buffer + deduplication + new-activities banner (ENC-TSK-B67
 * AC-9, AC-11).
 *
 * Incoming WebSocket events accumulate in this Zustand buffer and are NOT
 * auto-injected into the feed DOM (AC-11 — banner click is the only path into
 * the visible feed, preventing scroll disruption / layout shift).
 *
 * Deduplication (AC-9):
 *   Layer 1 (eventId): `inFlight` tracks eventIds from in-PWA optimistic
 *     mutations; an incoming event matching a known eventId REPLACES the
 *     optimistic version rather than prepending a duplicate.
 *   Layer 2 (eventual consistency): TanStack Query onSettled invalidation
 *     reconciles drift (handled in optimisticMutations).
 *   Layer 3 (cursor pagination): cursor-based getNextPageParam prevents
 *     duplicate page boundaries (handled in the infinite-query options).
 */

import { create } from 'zustand'
import type { FeedEvent } from './eventModel'

interface FeedBufferState {
  /** Buffered, not-yet-merged server events (newest first). */
  buffer: FeedEvent[]
  /** eventIds already known (optimistic in-flight or already merged). */
  seen: Set<string>
  /** eventIds of optimistic events still awaiting server confirmation. */
  inFlight: Set<string>
  /** Highest cursor observed — drives reconnect gap recovery. */
  lastReceivedCursor: number | null

  /** Count rendered by the "{N} new activities" banner. */
  bannerCount: () => number

  /** Register an optimistic event's id before the server echoes it back. */
  registerOptimistic: (eventId: string) => void
  /** Route an incoming server event into the buffer with full dedup. */
  ingest: (event: FeedEvent) => void
  /** Merge the buffer (banner click) and return the events to prepend. */
  drain: () => FeedEvent[]
  reset: () => void
}

export const useFeedBuffer = create<FeedBufferState>((set, get) => ({
  buffer: [],
  seen: new Set<string>(),
  inFlight: new Set<string>(),
  lastReceivedCursor: null,

  bannerCount: () => get().buffer.length,

  registerOptimistic: (eventId) =>
    set((s) => {
      const seen = new Set(s.seen)
      const inFlight = new Set(s.inFlight)
      seen.add(eventId)
      inFlight.add(eventId)
      return { seen, inFlight }
    }),

  ingest: (event) =>
    set((s) => {
      const cursor =
        s.lastReceivedCursor === null
          ? event.cursor
          : Math.max(s.lastReceivedCursor, event.cursor)

      // Layer 1: known eventId from an in-PWA optimistic mutation → replace the
      // optimistic version in place (no duplicate prepend).
      if (s.inFlight.has(event.eventId)) {
        const inFlight = new Set(s.inFlight)
        inFlight.delete(event.eventId)
        const buffer = s.buffer.map((e) =>
          e.eventId === event.eventId ? { ...event, pending: false } : e,
        )
        return { buffer, inFlight, lastReceivedCursor: cursor }
      }

      // Already buffered/merged → drop (idempotent under replay, AC-9).
      if (s.seen.has(event.eventId)) {
        return { lastReceivedCursor: cursor }
      }

      const seen = new Set(s.seen)
      seen.add(event.eventId)
      return {
        buffer: [event, ...s.buffer],
        seen,
        lastReceivedCursor: cursor,
      }
    }),

  drain: () => {
    const drained = get().buffer
    set({ buffer: [] })
    return drained
  },

  reset: () =>
    set({
      buffer: [],
      seen: new Set<string>(),
      inFlight: new Set<string>(),
      lastReceivedCursor: null,
    }),
}))
