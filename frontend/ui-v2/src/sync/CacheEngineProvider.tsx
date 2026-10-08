import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { getCacheEngine } from './cacheEngine'
import { seedCacheFromCorpus } from './corpusSeed'
import { getCorpusSeededAt, setCorpusSeededAt } from './feedVersionMeta'
import type { LocalSearchRecord } from '../types/search'
import { attachQueryClientPersist, restorePersistedQueryClient } from './queryPersist'
import { queryClient } from '../api/queryClient'

// ENC-TSK-M36 (feed data-truth): confirmed live against gamma that the
// authenticated /api/v1/feed/corpus this seed call depends on can take up
// to ~20s on a cold cache (backend fix in feed_query/lambda_function.py
// parallelizes the per-project fan-out that caused it), and a single
// transient failure here (a slow response the browser aborts, or an auth
// cookie not yet attached on the very first render) used to strand
// `isWarm` at false for the rest of the session -- there was no retry.
// Feed's search corpus falls back to a much thinner data set when
// `!isWarm` (buildSearchCorpus over realtime events only), which is the
// concrete mechanism behind "Home counts don't match Feed" and "gamma is
// missing plan/lesson records" symptoms: it isn't that gamma lacks the
// data (the same corpus endpoint serves Home's accurate counts), it's that
// the one-shot warm-up silently gave up.
const SEED_RETRY_DELAYS_MS = [1_000, 3_000]

export async function seedCacheFromCorpusWithRetry(): Promise<{
  pages: number
  records: number
  durationMs: number
}> {
  let lastError: unknown
  for (let attempt = 0; attempt <= SEED_RETRY_DELAYS_MS.length; attempt += 1) {
    try {
      return await seedCacheFromCorpus()
    } catch (error) {
      lastError = error
      const delay = SEED_RETRY_DELAYS_MS[attempt]
      if (delay === undefined) break
      await new Promise((resolve) => setTimeout(resolve, delay))
    }
  }
  throw lastError instanceof Error ? lastError : new Error('Corpus seed failed')
}

interface CacheEngineContextValue {
  isWarm: boolean
  warmDurationMs: number | null
  seedError: string | null
  /** ENC-TSK-Q33: the search-index rows as React state. The engine replaces
   *  its row array on every rebuild/upsert, so publishing that reference here
   *  is what makes /docs and /feed repaint when a seed lands. Reading
   *  getCacheEngine().searchIndex.all() during render did not: once the
   *  IndexedDB slice set isWarm, the post-seed setIsWarm(true) was a no-op and
   *  nothing re-rendered. */
  indexRows: LocalSearchRecord[]
  /** ISO time of the last corpus seed that completed on this device, or null. */
  lastSeededAt: string | null
}

const CacheEngineContext = createContext<CacheEngineContextValue>({
  isWarm: false,
  warmDurationMs: null,
  seedError: null,
  indexRows: [],
  lastSeededAt: null,
})

export function useCacheEngineState(): CacheEngineContextValue {
  return useContext(CacheEngineContext)
}

export function CacheEngineProvider({ children }: { children: ReactNode }) {
  const [isWarm, setIsWarm] = useState(getCacheEngine().isWarm)
  const [warmDurationMs, setWarmDurationMs] = useState<number | null>(null)
  const [seedError, setSeedError] = useState<string | null>(null)
  const [indexRows, setIndexRows] = useState<LocalSearchRecord[]>(() => getCacheEngine().searchIndex.all())
  const [lastSeededAt, setLastSeededAt] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    const engine = getCacheEngine()

    void (async () => {
      await restorePersistedQueryClient(queryClient)
      await engine.loadSearchSlice()
      const seededAt = await getCorpusSeededAt()
      if (!cancelled) {
        setIsWarm(engine.isWarm)
        setIndexRows(engine.searchIndex.all())
        setLastSeededAt(seededAt)
      }

      try {
        const result = await seedCacheFromCorpusWithRetry()
        if (cancelled) return
        const completedAt = new Date().toISOString()
        await setCorpusSeededAt(completedAt)
        setIsWarm(true)
        setIndexRows(engine.searchIndex.all())
        setWarmDurationMs(result.durationMs)
        setLastSeededAt(completedAt)
        setSeedError(null)
      } catch (error) {
        if (cancelled) return
        // Rows ingested before the failure are still newer than the slice.
        setIndexRows(engine.searchIndex.all())
        setSeedError(error instanceof Error ? error.message : 'Corpus seed failed')
      }
    })()

    const detachPersist = attachQueryClientPersist(queryClient)
    return () => {
      cancelled = true
      detachPersist()
    }
  }, [])

  return (
    <CacheEngineContext.Provider value={{ isWarm, warmDurationMs, seedError, indexRows, lastSeededAt }}>
      {children}
    </CacheEngineContext.Provider>
  )
}
