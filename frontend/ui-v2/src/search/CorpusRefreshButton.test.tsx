import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useCorpusRefreshAdapter } from './CorpusRefreshButton'
import { docsDeltaWanted } from './corpusSource'
import type { FeedRefreshAdapter } from '@io-kit/feed/react'

const state = vi.hoisted(() => ({
  corpus: {
    store: { getSeededAt: vi.fn() },
    refresh: vi.fn(),
  },
}))
vi.mock('./CorpusProvider', () => ({ useEnceladusCorpus: () => state.corpus }))

describe('useCorpusRefreshAdapter (ENC-TSK-R56-0A)', () => {
  let container: HTMLDivElement
  let root: Root
  let adapter!: FeedRefreshAdapter

  function Probe() {
    adapter = useCorpusRefreshAdapter()
    return null
  }

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    state.corpus.store.getSeededAt.mockReset()
    state.corpus.refresh.mockReset()
    act(() => root.render(<Probe />))
  })
  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  it('an authoritative refresh re-seeds with document deltas enabled and resolves the new sync stamp as asOf', async () => {
    state.corpus.store.getSeededAt.mockResolvedValueOnce('2026-10-27T00:00:00.000Z').mockResolvedValueOnce('2026-10-27T00:05:00.000Z')
    let docsDuring = false
    state.corpus.refresh.mockImplementation(async () => {
      docsDuring = docsDeltaWanted()
    })
    await expect(adapter.refresh({ authoritative: true })).resolves.toEqual({ asOf: '2026-10-27T00:05:00.000Z' })
    expect(state.corpus.refresh).toHaveBeenCalledWith({ seed: true })
    expect(docsDuring).toBe(true)
    expect(docsDeltaWanted()).toBe(false)
  })

  it('rejects when the corpus swallowed a failed sync (the stamp did not advance)', async () => {
    state.corpus.store.getSeededAt.mockResolvedValue('2026-10-27T00:00:00.000Z')
    state.corpus.refresh.mockResolvedValue(undefined)
    await expect(adapter.refresh({ authoritative: true })).rejects.toThrow('Refresh did not complete')
  })
})
