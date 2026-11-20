/**
 * ENC-TSK-T20 (ENC-PLN-108 W7-F5): a device holding a pre-W2.1 seed must re-seed once, on load.
 *
 * The bug this pins shipped to production and was visible immediately: 19 of 20 plan cards read "0 tree tasks in 0
 * waves" on a first load, because a delta only returns rows whose version_seq moved and SEED_MAX_AGE_MS sends an
 * ordinary load down the delta branch. Rows that had not changed since W2.1 widened the shape never came down again.
 * ENC-TSK-T13 fixed the refresh BUTTON; this is the first paint, which is what anyone actually sees.
 *
 * Asserted directly rather than left to observation, for the same reason the seed-age test gives: the app still
 * works, it is simply showing empty trees, and nothing fails loudly.
 */
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

let indexState: Record<string, unknown>
const refresh = vi.fn(async () => {})
const useCorpusIndex = vi.fn(() => indexState)

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

const { CorpusProvider, CORPUS_ROW_CONTRACT, needsContractReseed } = await import('./CorpusProvider')

const KEY = 'enceladus:corpus-row-contract'

let host: HTMLDivElement
let root: Root

const render = async (status = 'seeding') => {
  indexState = { rows: [], status, lastSeededAt: null, staleNotice: null, error: null, store: undefined, refresh, heal: () => {}, notifyReconnect: () => {} }
  await act(async () => {
    root.render(<CorpusProvider>{null}</CorpusProvider>)
  })
}

beforeEach(() => {
  refresh.mockClear()
  localStorage.clear()
  host = document.createElement('div')
  document.body.appendChild(host)
  root = createRoot(host)
})

afterEach(async () => {
  await act(async () => root.unmount())
  host.remove()
  localStorage.clear()
  vi.unstubAllGlobals()
})

describe('needsContractReseed', () => {
  it('is true for a device that has never recorded a contract', () => {
    expect(needsContractReseed(null)).toBe(true)
  })

  it('is true for a device holding an older contract', () => {
    expect(needsContractReseed('pre-w2.1')).toBe(true)
  })

  it('is false once the device matches this build', () => {
    expect(needsContractReseed(CORPUS_ROW_CONTRACT)).toBe(false)
  })
})

describe('CorpusProvider row-contract re-seed', () => {
  it('forces ONE authoritative seed when the stored contract is older', async () => {
    localStorage.setItem(KEY, 'pre-w2.1')
    await render()
    expect(refresh).toHaveBeenCalledTimes(1)
    expect(refresh).toHaveBeenCalledWith({ seed: true })
  })

  it('forces a seed when nothing was ever recorded', async () => {
    await render()
    expect(refresh).toHaveBeenCalledWith({ seed: true })
  })

  /** The steady state. Without this the fix would re-seed the whole corpus on every single load. */
  it('does not force a seed once the device is on this contract', async () => {
    localStorage.setItem(KEY, CORPUS_ROW_CONTRACT)
    await render()
    expect(refresh).not.toHaveBeenCalled()
  })

  it('records the contract only after a sync has actually succeeded', async () => {
    await render('seeding')
    expect(localStorage.getItem(KEY)).toBeNull()
    await render('live')
    expect(localStorage.getItem(KEY)).toBe(CORPUS_ROW_CONTRACT)
  })

  /**
   * refresh() resolves even when the sync failed -- useCorpusIndex catches and reports through status -- so writing
   * on the promise would mark a failed seed as done and strand the device on its old rows until the next shape
   * change. These two statuses are exactly the failure states the hook sets.
   */
  it.each(['stale', 'error'])('does NOT record the contract when the sync ended %s', async (status) => {
    await render(status)
    expect(localStorage.getItem(KEY)).toBeNull()
  })

  /** Private windows and blocked site data throw on access; that must degrade, not crash the whole app shell. */
  it('survives storage being denied, and still seeds', async () => {
    const denied = () => { throw new Error('SecurityError') }
    vi.stubGlobal('localStorage', { getItem: denied, setItem: denied, removeItem: denied, clear: () => {} })
    await expect(render()).resolves.toBeUndefined()
    expect(refresh).toHaveBeenCalledWith({ seed: true })
  })
})
