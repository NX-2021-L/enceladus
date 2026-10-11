import { describe, expect, it, vi } from 'vitest'
import { createHitView, feedHitCount, readRememberedServerTotal, rememberServerTotal, SERVER_TOTAL_STORAGE_KEY } from './hitView'
import type { SearchResultHit } from '../types/search'

const hit = (id: string, title = id): SearchResultHit => ({ recordId: id, recordType: 'task', projectId: 'enceladus', title, tier: 'local' })

function baseFeed() {
  let state: { items: unknown[]; status: string } = { items: [{ record_id: 'x' }], status: 'ready' }
  const ls = new Set<() => void>()
  return {
    getState: () => state,
    subscribe: (l: () => void) => (ls.add(l), () => ls.delete(l)),
    loadMore: vi.fn(async () => {}),
    source: { getId: (r: { record_id: string }) => r.record_id },
    set(next: typeof state) {
      state = next
      ls.forEach((l) => l())
    },
  }
}

describe('createHitView (DVP-TSK-931)', () => {
  it('serves the host hits as items, keeps base state, and delegates the engine methods', async () => {
    const base = baseFeed()
    const view = createHitView(base as never)
    view.setHits([hit('A'), hit('B')])
    expect(view.getState().items.map((h) => h.recordId)).toEqual(['A', 'B'])
    expect(view.getState().status).toBe('ready')
    expect(view.source.getId(hit('Q'))).toBe('Q')
    await view.loadMore()
    expect(base.loadMore).toHaveBeenCalledOnce()
  })

  it('returns a stable snapshot until hits or base state change, and notifies only on change', () => {
    const base = baseFeed()
    const view = createHitView(base as never)
    const seen = vi.fn()
    const off = view.subscribe(seen)
    view.setHits([hit('A')])
    const s1 = view.getState()
    expect(view.getState()).toBe(s1)
    view.setHits([hit('A')]) // same content, new objects: no notification, same snapshot
    expect(seen).toHaveBeenCalledTimes(1)
    expect(view.getState()).toBe(s1)
    view.setHits([hit('A', 'renamed')])
    expect(seen).toHaveBeenCalledTimes(2)
    base.set({ items: [], status: 'loading' })
    expect(seen).toHaveBeenCalledTimes(3)
    expect(view.getState().status).toBe('loading')
    off()
    view.setHits([])
    expect(seen).toHaveBeenCalledTimes(3)
  })
})

describe('feedHitCount (DVP-TSK-931 meta-line parity)', () => {
  it('shows the server corpus total when nothing narrows the feed, like the fully seeded legacy cache', () => {
    expect(feedHitCount(50, 9019, '', '')).toBe(9019)
  })
  it('counts matches once a query or property filter narrows the feed', () => {
    expect(feedHitCount(12, 9019, 'vagamod', '')).toBe(12)
    expect(feedHitCount(7, 9019, '', 'status:open')).toBe(7)
  })
  it('falls back to the loaded count until the server total arrives', () => {
    expect(feedHitCount(50, null, '', '')).toBe(50)
  })
})

describe('remembered server corpus total (DVP-TSK-947 first-paint count)', () => {
  const mem = () => {
    const m = new Map<string, string>()
    return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), m }
  }
  it('round-trips the last total so the first paint counts the corpus', () => {
    const s = mem()
    expect(readRememberedServerTotal(s)).toBeNull()
    rememberServerTotal(9027, s)
    expect(s.m.get(SERVER_TOTAL_STORAGE_KEY)).toBe('9027')
    expect(readRememberedServerTotal(s)).toBe(9027)
    expect(feedHitCount(50, readRememberedServerTotal(s), '', '')).toBe(9027)
  })
  it('ignores junk and survives blocked storage', () => {
    expect(readRememberedServerTotal({ getItem: () => 'nope' })).toBeNull()
    expect(readRememberedServerTotal({ getItem: () => '0' })).toBeNull()
    const boom = () => {
      throw new Error('SecurityError')
    }
    expect(readRememberedServerTotal({ getItem: boom })).toBeNull()
    expect(() => rememberServerTotal(1, { setItem: boom })).not.toThrow()
  })
})
