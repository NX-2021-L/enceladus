import { createContext, useContext, useEffect, type ReactNode } from 'react'
import { useCorpusIndex, type CorpusIndex } from '@io-kit/search/corpus'
import { queryClient } from '../api/queryClient'
import { attachQueryClientPersist, restorePersistedQueryClient } from '../sync/queryPersist'
import { CORPUS_BUDGET, createEnceladusCorpusSource, getEnceladusCorpusStore } from './corpusSource'

/**
 * DVP-TSK-995: one corpus index for the whole app (replaces CacheEngineProvider's seed). It paints from IndexedDB
 * first, then seeds and heals; /feed, /docs and the header launcher all read it. It also keeps the TanStack query
 * cache persistence the old provider owned.
 */
const source = createEnceladusCorpusSource()

const EMPTY: CorpusIndex = {
  rows: [],
  status: 'seeding',
  lastSeededAt: null,
  staleNotice: null,
  error: null,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- never read: the empty default only exists outside the provider (tests)
  store: undefined as any,
  refresh: async () => {},
}

const CorpusContext = createContext<CorpusIndex>(EMPTY)

export function useEnceladusCorpus(): CorpusIndex {
  return useContext(CorpusContext)
}

export function CorpusProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    void restorePersistedQueryClient(queryClient)
    return attachQueryClientPersist(queryClient)
  }, [])
  const index = useCorpusIndex(source, { store: getEnceladusCorpusStore(), budget: CORPUS_BUDGET })
  return <CorpusContext.Provider value={index}>{children}</CorpusContext.Provider>
}
