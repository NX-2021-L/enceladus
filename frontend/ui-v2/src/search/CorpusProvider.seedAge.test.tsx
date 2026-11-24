/**
 * ENC-TSK-S97-0E (ENC-PLN-108 W2.5, ruling D-23, criterion 24).
 *
 * The behaviour under test is one option, and the option is the whole point: useCorpusIndex defaults
 * seedMaxAgeMs to 0, which re-seeds the entire corpus on every cold load. At the measured 12,562 rows
 * and 4.58 MiB that is the single largest cost of opening the app. A regression here would be
 * invisible -- the app still works, just slower and more expensive every time -- so it is asserted
 * directly rather than left to observation.
 */
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const useCorpusIndex = vi.fn(() => ({
  rows: [],
  status: 'ready',
  lastSeededAt: null,
  staleNotice: null,
  error: null,
  store: undefined,
  refresh: async () => {},
  heal: () => {},
  notifyReconnect: () => {},
}))

vi.mock('@io-kit/search/corpus', () => ({ useCorpusIndex }))
vi.mock('../api/queryClient', () => ({ queryClient: {} }))
vi.mock('../sync/queryPersist', () => ({
  attachQueryClientPersist: () => () => {},
  restorePersistedQueryClient: async () => {},
}))
vi.mock('./corpusSource', () => ({
  CORPUS_BUDGET: { maxRows: 1 },
  acquireDocsDelta: () => () => {},
  createEnceladusCorpusSource: () => ({ id: 'test' }),
  docsDeltaWanted: () => false,
  getEnceladusCorpusStore: () => ({ name: 'test-store' }),
}))

const { CorpusProvider, SEED_MAX_AGE_MS } = await import('./CorpusProvider')

let host: HTMLDivElement
let root: Root

function mount() {
  act(() => {
    root.render(<CorpusProvider>{null}</CorpusProvider>)
  })
  return useCorpusIndex.mock.calls[0]?.[1] as Record<string, unknown>
}

describe('ENC-TSK-S97-0E warm start: the corpus seed age (ruling D-23)', () => {
  beforeEach(() => {
    useCorpusIndex.mockClear()
    host = document.createElement('div')
    document.body.appendChild(host)
    root = createRoot(host)
  })

  afterEach(() => {
    act(() => root.unmount())
    host.remove()
  })

  it('is exactly 24 hours', () => {
    expect(SEED_MAX_AGE_MS).toBe(86_400_000)
    expect(SEED_MAX_AGE_MS).toBe(24 * 60 * 60 * 1000)
  })

  it('reaches useCorpusIndex, so a cold load inside the window rides a delta instead of re-seeding', () => {
    const opts = mount()
    expect(useCorpusIndex).toHaveBeenCalled()
    expect(opts.seedMaxAgeMs).toBe(SEED_MAX_AGE_MS)
  })

  it('does not disturb the store, budget or 60s heal the provider already passed', () => {
    const opts = mount()
    expect(opts.store).toEqual({ name: 'test-store' })
    expect(opts.budget).toEqual({ maxRows: 1 })
    expect(opts.heal).toEqual({ intervalMs: 60_000 })
  })

  it('adds seedMaxAgeMs and nothing else, so refresh() still forces a full seed', () => {
    const opts = mount()
    expect(Object.keys(opts).sort()).toEqual(['budget', 'heal', 'seedMaxAgeMs', 'store'])
  })
})
