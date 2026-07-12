import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RealtimeFeedProvider, useRealtimeFeed, useRealtimeFeedEvents } from './RealtimeFeedProvider'
import { REALTIME_FEED_QUERY_KEY } from './feedEventReducer'
import { useFeedBufferStore } from '../store/feedBufferStore'
import type { RealtimeClientEvent } from './appsyncRealtimeClient'
import type { FeedRealtimeEvent } from '../types/feedEvents'

/**
 * ENC-TSK-K24 (B67 AC-9/AC-11/AC-15). No @testing-library/react in this
 * package — react-dom/client createRoot + act, matching the established
 * convention (src/primitives/SessionPrimitive.test.tsx).
 */

let capturedOnEvent: ((event: RealtimeClientEvent) => void) | null = null

vi.mock('../api/appsyncConfig', () => ({
  getAppSyncEventsConfig: () => ({
    httpHost: 'appsync.example.com',
    realtimeHost: 'appsync-realtime.example.com',
    apiKey: 'test-key',
    region: 'us-west-2',
    feedChannel: '/feed/updates',
    enabled: true,
  }),
}))

vi.mock('../api/feeds', () => ({
  fetchFeedSnapshot: () =>
    Promise.resolve({ events: [], hydratedAt: '2026-07-07T00:00:00Z', source: 's3' as const }),
}))

vi.mock('./appsyncRealtimeClient', () => ({
  AppSyncRealtimeClient: class {
    constructor(options: { onEvent: (event: RealtimeClientEvent) => void }) {
      capturedOnEvent = options.onEvent
    }
    start() {}
    stop() {}
    manualRetry() {}
    watchRecord() {
      return () => {}
    }
  },
}))

vi.mock('../sync/cacheEngine', () => ({
  getCacheEngine: () => ({
    upsertTier1: () => Promise.resolve(),
    markTombstone: () => Promise.resolve(),
  }),
  tier1FromFeedEvent: () => null,
}))

function pushEvent(event: FeedRealtimeEvent, latencyMs = 10) {
  capturedOnEvent?.({ type: 'feed_event', event, latencyMs })
}

function makeEvent(partial: Partial<FeedRealtimeEvent> & Pick<FeedRealtimeEvent, 'eventId' | 'cursor'>): FeedRealtimeEvent {
  return {
    recordId: 'ENC-TSK-K24',
    record_type: 'task',
    action: 'updated',
    actorType: 'agent',
    actorId: 'ENC-SES-001',
    summary: 'test event',
    channels: ['/feed/updates'],
    ...partial,
  }
}

describe('RealtimeFeedProvider — buffered live events (ENC-TSK-K24)', () => {
  let qc: QueryClient
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    capturedOnEvent = null
    useFeedBufferStore.getState().clear()
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
    qc.clear()
  })

  function Consumer() {
    // ENC-TSK-M73 (B67 AC-13): the visible list is read from the
    // REALTIME_FEED_QUERY_KEY cache via the shared hook — no ctx.events copy.
    const events = useRealtimeFeedEvents()
    return (
      <ul data-testid="visible-events">
        {events.map((e) => (
          <li key={e.eventId}>{e.eventId}</li>
        ))}
      </ul>
    )
  }

  it('a live-pushed event does NOT appear in the visible list — it only lands in the buffer (no auto-inject)', async () => {
    act(() => {
      root.render(
        <QueryClientProvider client={qc}>
          <RealtimeFeedProvider>
            <Consumer />
          </RealtimeFeedProvider>
        </QueryClientProvider>,
      )
    })
    await act(async () => {
      await Promise.resolve()
    })

    await act(async () => {
      pushEvent(makeEvent({ eventId: 'live-1', cursor: 100 }))
      await Promise.resolve()
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    expect(container.querySelector('[data-testid="visible-events"]')?.textContent).toBe('')
    expect(useFeedBufferStore.getState().bufferedEvents.map((e) => e.eventId)).toEqual(['live-1'])
  })

  it('mergeBufferedEvents() moves buffered events into the visible list and drains the buffer', async () => {
    let ctx!: ReturnType<typeof useRealtimeFeed>
    function CaptureConsumer() {
      ctx = useRealtimeFeed()
      const events = useRealtimeFeedEvents()
      return (
        <ul data-testid="visible-events">
          {events.map((e) => (
            <li key={e.eventId}>{e.eventId}</li>
          ))}
        </ul>
      )
    }

    act(() => {
      root.render(
        <QueryClientProvider client={qc}>
          <RealtimeFeedProvider>
            <CaptureConsumer />
          </RealtimeFeedProvider>
        </QueryClientProvider>,
      )
    })
    await act(async () => {
      await Promise.resolve()
    })

    await act(async () => {
      pushEvent(makeEvent({ eventId: 'live-1', cursor: 100 }))
      pushEvent(makeEvent({ eventId: 'live-2', cursor: 101 }))
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    expect(useFeedBufferStore.getState().bufferedEvents).toHaveLength(2)

    await act(async () => {
      ctx.mergeBufferedEvents()
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    const ids = Array.from(container.querySelectorAll('[data-testid="visible-events"] li')).map((el) => el.textContent)
    expect(ids.sort()).toEqual(['live-1', 'live-2'])
    expect(useFeedBufferStore.getState().bufferedEvents).toHaveLength(0)
  })

  it('redelivering the same eventId (reconnect replay) never produces a duplicate after merge (AC-9)', async () => {
    let ctx!: ReturnType<typeof useRealtimeFeed>
    function CaptureConsumer() {
      ctx = useRealtimeFeed()
      return null
    }

    act(() => {
      root.render(
        <QueryClientProvider client={qc}>
          <RealtimeFeedProvider>
            <CaptureConsumer />
          </RealtimeFeedProvider>
        </QueryClientProvider>,
      )
    })
    await act(async () => {
      await Promise.resolve()
    })

    // First delivery, arrives, buffers, gets merged.
    await act(async () => {
      pushEvent(makeEvent({ eventId: 'replay-1', cursor: 50 }))
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    await act(async () => {
      ctx.mergeBufferedEvents()
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    const afterFirst = qc.getQueryData<FeedRealtimeEvent[]>(REALTIME_FEED_QUERY_KEY) ?? []
    expect(afterFirst.map((e) => e.eventId)).toEqual(['replay-1'])

    // Same eventId redelivered post-reconnect (replay-from-cursor overlap).
    await act(async () => {
      pushEvent(makeEvent({ eventId: 'replay-1', cursor: 50 }))
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    await act(async () => {
      ctx.mergeBufferedEvents()
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    const afterReplay = qc.getQueryData<FeedRealtimeEvent[]>(REALTIME_FEED_QUERY_KEY) ?? []
    expect(afterReplay.filter((e) => e.eventId === 'replay-1')).toHaveLength(1)
  })

  it('a burst of rapid live events does not corrupt or drop buffered state (AC-15 low-priority scheduling proxy)', async () => {
    act(() => {
      root.render(
        <QueryClientProvider client={qc}>
          <RealtimeFeedProvider>
            <Consumer />
          </RealtimeFeedProvider>
        </QueryClientProvider>,
      )
    })
    await act(async () => {
      await Promise.resolve()
    })

    await act(async () => {
      for (let i = 0; i < 25; i += 1) {
        pushEvent(makeEvent({ eventId: `burst-${i}`, cursor: 1000 + i }))
      }
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    expect(useFeedBufferStore.getState().bufferedEvents).toHaveLength(25)
    // The visible list is still untouched — a burst of pushes is exactly
    // the scenario the buffer exists to absorb without ever forcing an
    // uncontrolled render storm on the rendered list.
    expect(container.querySelector('[data-testid="visible-events"]')?.textContent).toBe('')
  })

  it('the consumer view is the REALTIME_FEED_QUERY_KEY cache itself — no divergent component-local copy (AC-13)', async () => {
    let ctx!: ReturnType<typeof useRealtimeFeed>
    let hookEvents: FeedRealtimeEvent[] = []
    function CaptureConsumer() {
      ctx = useRealtimeFeed()
      hookEvents = useRealtimeFeedEvents()
      return null
    }

    act(() => {
      root.render(
        <QueryClientProvider client={qc}>
          <RealtimeFeedProvider>
            <CaptureConsumer />
          </RealtimeFeedProvider>
        </QueryClientProvider>,
      )
    })
    await act(async () => {
      await Promise.resolve()
    })

    await act(async () => {
      pushEvent(makeEvent({ eventId: 'a', cursor: 1 }))
      pushEvent(makeEvent({ eventId: 'b', cursor: 2 }))
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    await act(async () => {
      ctx.mergeBufferedEvents()
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    const cache = qc.getQueryData<FeedRealtimeEvent[]>(REALTIME_FEED_QUERY_KEY) ?? []
    expect(cache.map((e) => e.eventId).sort()).toEqual(['a', 'b'])
    // Same contents AND same array reference: the consumer holds no copy that
    // could drift from the cache — the cache is the sole source of truth.
    expect(hookEvents).toEqual(cache)
    expect(hookEvents).toBe(cache)
  })
})
