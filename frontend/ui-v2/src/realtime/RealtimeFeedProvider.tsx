import {
  createContext,
  startTransition,
  useContext,
  useEffect,
  useRef,
  type ReactNode,
} from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { getAppSyncEventsConfig } from '../api/appsyncConfig'
import { fetchFeedSnapshot } from '../api/feeds'
import {
  AppSyncRealtimeClient,
  type RealtimeClientEvent,
} from './appsyncRealtimeClient'
import {
  REALTIME_FEED_QUERY_KEY,
  maxCursor,
  mergeFeedEvents,
  snapshotToFeedState,
} from './feedEventReducer'
import { useFeedConnectionStore } from '../store/feedConnectionStore'
import { useFeedBufferStore } from '../store/feedBufferStore'
import type { FeedRealtimeEvent } from '../types/feedEvents'
import { getCacheEngine, tier1FromFeedEvent } from '../sync/cacheEngine'

interface RealtimeFeedContextValue {
  isHydrating: boolean
  isSnapshotError: boolean
  refetchSnapshot: () => void
  manualReconnect: () => void
  /**
   * ENC-TSK-K24 (B67 AC-11): merges every buffered "new activity" into the
   * visible list in one call — the only way a live-pushed event reaches the
   * REALTIME_FEED_QUERY_KEY cache (ENC-TSK-M73). Returns the number merged so
   * the caller (FeedPane's banner) can decide whether to scroll to top.
   */
  mergeBufferedEvents: () => number
  /**
   * ENC-TSK-L29: subscribe to full-body events for a single record over the
   * shared realtime connection. No-op (safe, returns a no-op unsubscribe) if
   * realtime is disabled or not yet connected.
   */
  watchRecord: (recordId: string, onEvent: (event: FeedRealtimeEvent) => void) => () => void
}

const RealtimeFeedContext = createContext<RealtimeFeedContextValue | null>(null)

export function useRealtimeFeed(): RealtimeFeedContextValue {
  const ctx = useContext(RealtimeFeedContext)
  if (!ctx) throw new Error('useRealtimeFeed must be used within RealtimeFeedProvider')
  return ctx
}

/**
 * ENC-TSK-M73 (B67 AC-13): the visible feed-event list lives SOLELY in the
 * TanStack Query cache at REALTIME_FEED_QUERY_KEY — there is no parallel
 * component useState copy. This hook subscribes consumers (FeedPane,
 * FeedRoute, DocsRoute) to that single cache entry so they re-render when the
 * provider mutates it via setQueryData (snapshot seed + banner-merge drain).
 * The queryFn only ever returns the current cached value — every write comes
 * exclusively from setQueryData inside the provider — and staleTime:Infinity
 * means it is never refetched or clobbered.
 */
export function useRealtimeFeedEvents(): FeedRealtimeEvent[] {
  const queryClient = useQueryClient()
  const { data } = useQuery<FeedRealtimeEvent[]>({
    queryKey: REALTIME_FEED_QUERY_KEY,
    queryFn: () => queryClient.getQueryData<FeedRealtimeEvent[]>(REALTIME_FEED_QUERY_KEY) ?? [],
    initialData: () => queryClient.getQueryData<FeedRealtimeEvent[]>(REALTIME_FEED_QUERY_KEY) ?? [],
    staleTime: Infinity,
    gcTime: Infinity,
  })
  return data
}

export function RealtimeFeedProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const clientRef = useRef<AppSyncRealtimeClient | null>(null)

  const setPhase = useFeedConnectionStore((s) => s.setPhase)
  const setReconnectAttempt = useFeedConnectionStore((s) => s.setReconnectAttempt)
  const resetFailedReconnects = useFeedConnectionStore((s) => s.resetFailedReconnects)
  const recordLatency = useFeedConnectionStore((s) => s.recordLatency)
  const setErrorMessage = useFeedConnectionStore((s) => s.setErrorMessage)

  const snapshotQuery = useQuery({
    queryKey: ['feed-snapshot'],
    queryFn: fetchFeedSnapshot,
    staleTime: 60_000,
    retry: 2,
  })

  useEffect(() => {
    if (!snapshotQuery.data) return
    const seeded = snapshotToFeedState(snapshotQuery.data)
    const merged = mergeFeedEvents(seeded, queryClient.getQueryData<FeedRealtimeEvent[]>(REALTIME_FEED_QUERY_KEY) ?? [])
    queryClient.setQueryData(REALTIME_FEED_QUERY_KEY, merged)
  }, [snapshotQuery.data, queryClient])

  useEffect(() => {
    const config = getAppSyncEventsConfig()
    if (!config.enabled) {
      setPhase('disconnected')
      setErrorMessage('AppSync realtime not configured — S3 snapshot only')
      return
    }

    const events = queryClient.getQueryData<FeedRealtimeEvent[]>(REALTIME_FEED_QUERY_KEY) ?? []
    const initialCursor = maxCursor(events)

    const handleClientEvent = (event: RealtimeClientEvent) => {
      switch (event.type) {
        case 'connected':
          setPhase('connected')
          resetFailedReconnects()
          setErrorMessage(null)
          break
        case 'reconnecting':
          setPhase('reconnecting')
          setReconnectAttempt(event.attempt)
          break
        case 'disconnected':
          setPhase('disconnected')
          setErrorMessage(event.reason)
          break
        case 'manual_retry_required':
          setPhase('manual_retry')
          setErrorMessage('Live feed disconnected after 12 reconnect attempts')
          break
        case 'feed_event':
          recordLatency(event.latencyMs)
          void (async () => {
            const engine = getCacheEngine()
            const feedEvent = event.event
            const tier1 = tier1FromFeedEvent({
              recordId: feedEvent.recordId,
              recordType: feedEvent.record_type,
              projectId: '',
              title: feedEvent.summary,
              status: feedEvent.action,
            })
            if (!tier1) return
            if (feedEvent.action === 'removed') {
              await engine.markTombstone(tier1.recordKey, tier1.recordId)
            } else {
              await engine.upsertTier1(tier1)
            }
          })()
          // ENC-TSK-K24 (B67 AC-11): buffer, never auto-inject. AC-15:
          // startTransition keeps this low-priority relative to anything
          // the user is actively doing (typing, clicking) — a burst of
          // live events must not compete with input responsiveness.
          startTransition(() => {
            useFeedBufferStore.getState().bufferEvent(event.event)
          })
          break
        case 'gap_too_large':
          setErrorMessage(event.signal.reason)
          void snapshotQuery.refetch()
          break
        default:
          break
      }
    }

    setPhase('connecting')
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: initialCursor,
      onEvent: handleClientEvent,
    })
    clientRef.current = client
    client.start()

    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        client.manualRetry()
      }
    }
    document.addEventListener('visibilitychange', onVisibility)

    return () => {
      document.removeEventListener('visibilitychange', onVisibility)
      client.stop()
      clientRef.current = null
    }
  }, [
    queryClient,
    recordLatency,
    resetFailedReconnects,
    setErrorMessage,
    setPhase,
    setReconnectAttempt,
    snapshotQuery,
  ])

  const value: RealtimeFeedContextValue = {
    isHydrating: snapshotQuery.isPending,
    isSnapshotError: snapshotQuery.isError,
    refetchSnapshot: () => {
      void snapshotQuery.refetch()
    },
    manualReconnect: () => {
      clientRef.current?.manualRetry()
      resetFailedReconnects()
      setPhase('connecting')
    },
    mergeBufferedEvents: () => {
      const drained = useFeedBufferStore.getState().drainBuffer()
      if (drained.length === 0) return 0
      // ENC-TSK-M73 (B67 AC-13): merge into the REALTIME_FEED_QUERY_KEY cache
      // — the sole source of truth — instead of a parallel useState copy. The
      // startTransition wrapping (B67 AC-15) and buffer-drain semantics
      // (AC-11) are preserved exactly; only the write target changed.
      startTransition(() => {
        const prev = queryClient.getQueryData<FeedRealtimeEvent[]>(REALTIME_FEED_QUERY_KEY) ?? []
        const merged = mergeFeedEvents(prev, drained)
        queryClient.setQueryData(REALTIME_FEED_QUERY_KEY, merged)
      })
      return drained.length
    },
    watchRecord: (recordId, onRecordEvent) => {
      if (!clientRef.current) return () => {}
      return clientRef.current.watchRecord(recordId, onRecordEvent)
    },
  }

  return <RealtimeFeedContext.Provider value={value}>{children}</RealtimeFeedContext.Provider>
}
