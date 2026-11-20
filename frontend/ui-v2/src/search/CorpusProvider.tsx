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

/**
 * ENC-TSK-S97-0E (ENC-PLN-108 W2.5, ruling D-23 and criterion 24): a device does ONE full corpus seed a day and
 * rides deltas in between. useCorpusIndex defaults seedMaxAgeMs to 0, which means every cold load re-seeds the
 * whole corpus; at the measured 12,562 rows / 4.58 MiB that is the single largest cost of opening the app.
 *
 * Known and accepted cost (D-23): document rows can be up to a day stale in the header search launcher until Docs
 * is opened, because the documents-table scan (doc_since) is gated separately in corpusSource (P101-R15) and only
 * a full seed otherwise refreshes them. Tracker rows do NOT go stale -- they heal on the 60 s delta above.
 *
 * refresh({ seed: true }) forces a full seed, so CorpusRefreshButton's authoritative mode remains the escape
 * hatch. Note the flag: a bare refresh() does NOT re-seed while the stored seed is younger than this constant --
 * the kit's sync() computes `doSeed = o.seed === true || !(fresh && haveCursors)` and takes the delta-only branch.
 * Any caller that needs the current row SHAPE, not just current values, must pass it; a delta returns only rows
 * whose version_seq moved, so a widened row never reaches a record that has not changed since.
 */
const SEED_MAX_AGE_MS = 24 * 60 * 60 * 1000

const EMPTY: CorpusIndex = {
  rows: [],
  status: 'seeding',
  lastSeededAt: null,
  staleNotice: null,
  error: null,
  storageFault: null,
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

export { SEED_MAX_AGE_MS }

/**
 * ENC-TSK-T20 (ENC-PLN-108 W7-F5): the ROW CONTRACT this build expects from the corpus.
 *
 * Bump this string whenever the corpus row SHAPE changes -- a new attribute the client reads, or one removed. It is
 * not a cache buster for row VALUES, which the heal loop already keeps current; it is specifically about shape.
 *
 * Why it has to exist. A delta only returns rows whose version_seq moved, and SEED_MAX_AGE_MS sends an ordinary load
 * down the delta branch while the stored seed is under a day old. So when ENC-TSK-S97-0A (W2.1) widened the row with
 * objectives_set, parent and wave, every device holding an older seed kept its pre-W2.1 rows INDEFINITELY: those
 * records had not changed, so no delta ever carried them again. Measured on prod the moment the Plans page shipped,
 * on a load that had not been manually refreshed: 0 corpus pages, 19 of 20 plan cards reading '0 tree tasks in 0
 * waves', 1 wave, 0 parent links. One authoritative refresh fetched 27 corpus pages and the same page became 132
 * waves, 128 of them parent-derived, with 107 parent links. The page was right; the data was old.
 *
 * ENC-TSK-T13 made the Plans page's refresh control authoritative, which fixes this ONLY for a user who presses it.
 * This fixes the first paint, which is what anyone actually sees.
 */
export const CORPUS_ROW_CONTRACT = 'w2.1-objectives-set+parent+wave'
const CONTRACT_KEY = 'enceladus:corpus-row-contract'

const readContract = (): string | null => {
  try {
    return localStorage.getItem(CONTRACT_KEY)
  } catch {
    // Storage denied (private window, blocked site data). Returning null forces one seed per load, which is
    // correct-but-costly rather than wrong, and matches what a device with no persisted corpus does anyway.
    return null
  }
}
const writeContract = (): void => {
  try {
    localStorage.setItem(CONTRACT_KEY, CORPUS_ROW_CONTRACT)
  } catch {
    /* best effort, exactly like the corpus store's own persistence */
  }
}

/** Pure so the decision is testable without a provider: a stored contract that is not this one needs a re-seed. */
export const needsContractReseed = (stored: string | null): boolean => stored !== CORPUS_ROW_CONTRACT

export function CorpusProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    void restorePersistedQueryClient(queryClient)
    return attachQueryClientPersist(queryClient)
  }, [])
  const index = useCorpusIndex(source, {
    store: getEnceladusCorpusStore(),
    budget: CORPUS_BUDGET,
    heal: HEAL,
    seedMaxAgeMs: SEED_MAX_AGE_MS,
  })

  const { refresh, status } = index
  // One forced seed when the stored contract is older than this build's. seedCorpus coalesces with the mount sync
  // already in flight (useCorpusIndex returns the inflight promise), so a cold device does not seed twice.
  useEffect(() => {
    if (!needsContractReseed(readContract())) return
    void refresh({ seed: true })
  }, [refresh])

  // Record the contract only once a sync has actually SUCCEEDED. refresh() resolves even when the sync failed --
  // the hook catches and reports through status -- so writing on the promise would mark a failed seed as done and
  // strand the device on its old rows until the next shape change.
  useEffect(() => {
    if (status === 'live') writeContract()
  }, [status])

  return <CorpusContext.Provider value={index}>{children}</CorpusContext.Provider>
}
