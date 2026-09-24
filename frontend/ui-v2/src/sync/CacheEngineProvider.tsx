import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { getCacheEngine } from './cacheEngine'
import { seedCacheFromCorpus } from './corpusSeed'
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
}

const CacheEngineContext = createContext<CacheEngineContextValue>({
  isWarm: false,
  warmDurationMs: null,
  seedError: null,
})

export function useCacheEngineState(): CacheEngineContextValue {
  return useContext(CacheEngineContext)
}

export function CacheEngineProvider({ children }: { children: ReactNode }) {
  const [isWarm, setIsWarm] = useState(getCacheEngine().isWarm)
  const [warmDurationMs, setWarmDurationMs] = useState<number | null>(null)
  const [seedError, setSeedError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    const engine = getCacheEngine()

    void (async () => {
      await restorePersistedQueryClient(queryClient)
      await engine.loadSearchSlice()
      if (!cancelled) setIsWarm(engine.isWarm)

      try {
        const result = await seedCacheFromCorpusWithRetry()
        if (cancelled) return
        setIsWarm(true)
        setWarmDurationMs(result.durationMs)
        setSeedError(null)
      } catch (error) {
        if (cancelled) return
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
    <CacheEngineContext.Provider value={{ isWarm, warmDurationMs, seedError }}>
      {children}
    </CacheEngineContext.Provider>
  )
}
