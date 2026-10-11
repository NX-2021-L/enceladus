import { describe, expect, it, vi } from 'vitest'
import { createHitView } from './hitView'
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
