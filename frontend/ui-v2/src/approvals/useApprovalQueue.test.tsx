import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'
import { ApprovalDecisionError, type ApprovalAdapter } from './types'
import { useApprovalQueue, type ApprovalQueue } from './useApprovalQueue'

interface Item { id: string; v: number }
type Q = ApprovalQueue<Item, string, string>

async function mount(adapter: ApprovalAdapter<Item, string, string>) {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  const ref: { q: Q | null } = { q: null }
  function Probe() { ref.q = useApprovalQueue(adapter); return null }
  const root = createRoot(document.createElement('div'))
  await act(async () => { root.render(<Probe />) })
  return { get q() { return ref.q as Q }, unmount: () => act(() => root.unmount()) }
}

const base = (decide: ApprovalAdapter<Item, string, string>['decide']): ApprovalAdapter<Item, string, string> => ({
  list: async () => [{ id: 'a', v: 1 }, { id: 'b', v: 1 }, { id: 'c', v: 1 }],
  key: (i) => i.id,
  version: (i) => i.v,
  decide,
})

describe('useApprovalQueue', () => {
  it('lists and selects', async () => {
    const h = await mount(base(vi.fn()))
    expect(h.q.items.map((i) => i.id)).toEqual(['a', 'b', 'c'])
    await act(async () => h.q.setSelection(['a', 'c']))
    expect(h.q.selectedItems.map((i) => i.id)).toEqual(['a', 'c'])
    h.unmount()
  })

  it('bulk is one decide call per selected item, with its own payload', async () => {
    const decide = vi.fn(async (i: Item, _v, p: string) => `${i.id}:${p}`)
    const h = await mount(base(decide))
    await act(async () => h.q.setSelection(['a', 'b']))
    await act(async () => { await h.q.decideSelected('approve', (i) => `P${i.id}`) })
    expect(decide).toHaveBeenCalledTimes(2)
    expect(decide.mock.calls.map((c) => [c[0].id, c[1], c[2]])).toEqual([['a', 'approve', 'Pa'], ['b', 'approve', 'Pb']])
    expect(h.q.results.map((r) => r.outcome)).toEqual(['a:Pa', 'b:Pb'])
    expect(h.q.items.map((i) => i.id)).toEqual(['c'])
    expect(h.q.progress).toEqual({ running: false, done: 2, total: 2 })
    h.unmount()
  })

  it('a failure never stops the rest; the failed row stays', async () => {
    const decide = vi.fn(async (i: Item) => {
      if (i.id === 'a') throw new ApprovalDecisionError(409, 'ID taken')
      if (i.id === 'b') throw new Error('boom')
      return 'ok'
    })
    const h = await mount(base(decide))
    await act(async () => h.q.setSelection(['a', 'b', 'c']))
    await act(async () => { await h.q.decideSelected('approve', () => '') })
    expect(decide).toHaveBeenCalledTimes(3)
    expect(h.q.results.map((r) => r.state)).toEqual(['conflict', 'error', 'ok'])
    expect(h.q.items.map((i) => i.id)).toEqual(['a', 'b'])
    expect([...h.q.selected].sort()).toEqual(['a', 'b'])
    h.unmount()
  })

  it('a 412 returns the refreshed item to its row', async () => {
    const decide = vi.fn(async (i: Item) => {
      if (i.id === 'b') throw new ApprovalDecisionError<Item>(412, 'changed', { id: 'b', v: 7 })
      return 'ok'
    })
    const h = await mount(base(decide))
    await act(async () => h.q.setSelection(['a', 'b']))
    await act(async () => { await h.q.decideSelected('reject', () => '') })
    expect(h.q.results.find((r) => r.key === 'b')).toMatchObject({ state: 'conflict', status: 412 })
    expect(h.q.items.find((i) => i.id === 'b')?.v).toBe(7)
    expect(h.q.items.find((i) => i.id === 'a')).toBeUndefined()
    h.unmount()
  })
})
