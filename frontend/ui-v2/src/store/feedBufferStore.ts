/**
 * ENC-TSK-K24 (B67 AC-11): live realtime feed events never auto-inject into
 * the rendered list — DOC-E470AC8CE9A8 §5.1 is explicit that auto-prepend is
 * a chat-interface pattern, not appropriate here ("This is the pattern used
 * by GitHub, Linear, and most production activity feeds"). Every event that
 * arrives after initial snapshot hydration accumulates here instead; the
 * FeedPane banner ("{N} new activities") is the only way they reach the
 * visible list, via `mergeBuffer()`.
 */

import { create } from 'zustand'
import type { FeedRealtimeEvent } from '../types/feedEvents'

interface FeedBufferState {
  bufferedEvents: FeedRealtimeEvent[]
  bufferEvent: (event: FeedRealtimeEvent) => void
  /** Returns the buffered events (for the caller to merge into the visible
   * list) and clears the buffer in the same call — there is no window where
   * an event is counted as both buffered and merged. */
  drainBuffer: () => FeedRealtimeEvent[]
  clear: () => void
}

export const useFeedBufferStore = create<FeedBufferState>((set, get) => ({
  bufferedEvents: [],

  bufferEvent: (event) => {
    set((state) => {
      // De-dupe within the buffer itself (a reconnect replay can redeliver
      // an eventId that's already waiting to be merged).
      if (state.bufferedEvents.some((e) => e.eventId === event.eventId)) {
        return state
      }
      return { bufferedEvents: [...state.bufferedEvents, event] }
    })
  },

  drainBuffer: () => {
    const events = get().bufferedEvents
    set({ bufferedEvents: [] })
    return events
  },

  clear: () => set({ bufferedEvents: [] }),
}))
