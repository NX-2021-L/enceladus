import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { getCacheEngine } from './cacheEngine'
import { seedCacheFromCorpus } from './corpusSeed'
import { attachQueryClientPersist, restorePersistedQueryClient } from './queryPersist'
import { queryClient } from '../api/queryClient'

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
        const result = await seedCacheFromCorpus()
        if (cancelled) return
        setIsWarm(true)
        setWarmDurationMs(result.durationMs)
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
