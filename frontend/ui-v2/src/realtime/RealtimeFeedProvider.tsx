import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
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
import type { FeedRealtimeEvent } from '../types/feedEvents'

interface RealtimeFeedContextValue {
  events: FeedRealtimeEvent[]
  isHydrating: boolean
  isSnapshotError: boolean
  refetchSnapshot: () => void
  manualReconnect: () => void
}

const RealtimeFeedContext = createContext<RealtimeFeedContextValue | null>(null)

export function useRealtimeFeed(): RealtimeFeedContextValue {
  const ctx = useContext(RealtimeFeedContext)
  if (!ctx) throw new Error('useRealtimeFeed must be used within RealtimeFeedProvider')
  return ctx
}

export function RealtimeFeedProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const clientRef = useRef<AppSyncRealtimeClient | null>(null)
  const [events, setEvents] = useState<FeedRealtimeEvent[]>([])

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
    setEvents(merged)
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
          setEvents((prev) => {
            const merged = mergeFeedEvents(prev, [event.event])
            queryClient.setQueryData(REALTIME_FEED_QUERY_KEY, merged)
            return merged
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
    events,
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
  }

  return <RealtimeFeedContext.Provider value={value}>{children}</RealtimeFeedContext.Provider>
}
