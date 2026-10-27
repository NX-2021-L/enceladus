import { createContext, useContext, useEffect, type ReactNode } from 'react'
import { useCorpusIndex, type CorpusIndex } from '@io-kit/search/corpus'
import { queryClient } from '../api/queryClient'
import { attachQueryClientPersist, restorePersistedQueryClient } from '../sync/queryPersist'
import {
  CORPUS_BUDGET,
  acquireDocsDelta,
  createEnceladusCorpusSource,
  docsDeltaWanted,
  getEnceladusCorpusStore,
} from './corpusSource'

/**
 * DVP-TSK-995: one corpus index for the whole app (replaces CacheEngineProvider's seed). It paints from IndexedDB
 * first, then seeds and heals; /feed, /docs and the header launcher all read it. It also keeps the TanStack query
 * cache persistence the old provider owned.
 */
const source = createEnceladusCorpusSource(undefined, docsDeltaWanted)

/**
 * ENC-TSK-R56-0A (@io-kit/search 1.1 heal): the kit heals on a 60 s visible-only interval plus visibility, focus and
 * online, and pauses while the tab is hidden. Delta-only with a server-cursor overlap, so a heal is cheap; the
 * documents-table scan (doc_since) is gated separately in corpusSource (P101-R15).
 */
const HEAL = { intervalMs: 60_000 } as const

const EMPTY: CorpusIndex = {
  rows: [],
  status: 'seeding',
  lastSeededAt: null,
  staleNotice: null,
  error: null,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- never read: the empty default only exists outside the provider (tests)
  store: undefined as any,
  refresh: async () => {},
  heal: () => {},
  notifyReconnect: () => {},
}

const CorpusContext = createContext<CorpusIndex>(EMPTY)

export function useEnceladusCorpus(): CorpusIndex {
  return useContext(CorpusContext)
}

/**
 * Mount in the Docs page. While mounted, delta heals include doc_since (P101-R15) and one heal runs on mount to
 * catch the document cursor up with whatever Feed-only heals skipped.
 */
export function useDocsDeltaWhileMounted(): void {
  const { heal } = useEnceladusCorpus()
  useEffect(() => {
    const release = acquireDocsDelta()
    heal('docs-mounted')
    return release
  }, [heal])
}

export function CorpusProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    void restorePersistedQueryClient(queryClient)
    return attachQueryClientPersist(queryClient)
  }, [])
  const index = useCorpusIndex(source, { store: getEnceladusCorpusStore(), budget: CORPUS_BUDGET, heal: HEAL })
  return <CorpusContext.Provider value={index}>{children}</CorpusContext.Provider>
}
