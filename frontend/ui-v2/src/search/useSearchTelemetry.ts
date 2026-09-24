import { useEffect, useRef } from 'react'
import { useFeedConnectionStore } from '../store/feedConnectionStore'

/** Record keystroke → suggestion panel refresh latency (p50/p95 in feedConnectionStore). */
export function useKeystrokeSuggestionTelemetry(suggestionsKey: string) {
  const record = useFeedConnectionStore((s) => s.recordKeystrokeSuggestion)
  const pendingAt = useRef<number | null>(null)

  const markKeystroke = () => {
    pendingAt.current = performance.now()
  }

  useEffect(() => {
    if (pendingAt.current === null) return
    record(performance.now() - pendingAt.current)
    pendingAt.current = null
  }, [suggestionsKey, record])

  return { markKeystroke }
}

/** Record request → first-page latency split by local (sync tier) vs server (hybrid tier). */
export function useRequestFirstPageTelemetry(
  requestKey: string,
  hybridEnabled: boolean,
  hybridPending: boolean,
) {
  const recordLocal = useFeedConnectionStore((s) => s.recordRequestFirstPageLocal)
  const recordServer = useFeedConnectionStore((s) => s.recordRequestFirstPageServer)
  const startedAt = useRef<number | null>(null)
  const localKey = useRef<string | null>(null)
  const serverKey = useRef<string | null>(null)

  useEffect(() => {
    startedAt.current = performance.now()
    localKey.current = null
    serverKey.current = null
  }, [requestKey])

  useEffect(() => {
    if (!startedAt.current || localKey.current === requestKey) return
    recordLocal(performance.now() - startedAt.current)
    localKey.current = requestKey
  }, [requestKey, recordLocal])

  useEffect(() => {
    if (!hybridEnabled || !startedAt.current || serverKey.current === requestKey) return
    if (hybridPending) return
    recordServer(performance.now() - startedAt.current)
    serverKey.current = requestKey
  }, [requestKey, hybridEnabled, hybridPending, recordServer])
}
