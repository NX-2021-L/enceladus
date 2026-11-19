import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { PlansRow } from './planView'

/**
 * ENC-TSK-S98-0C (ENC-PLN-108 W3.3): the corpus-to-lens adapter.
 *
 * The split under test is ruling D-26 and D-28 made real: STRUCTURE (parent, wave, objectives_set, status) comes
 * from the corpus, which is already seeded on every route, and the three lifecycle TIMESTAMPS come from
 * ENC-TSK-T05's plan-scoped read. The page must therefore draw complete wave structure before that read lands, and
 * must make exactly ONE such request per page open (ENC-TSK-T05 AC-4).
 */

let corpusState: {
  rows: unknown[]
  status: string
  lastSeededAt: string | null
  staleNotice: unknown
  error: unknown
  refresh: () => Promise<void>
}

vi.mock('../search/CorpusProvider', () => ({ useEnceladusCorpus: () => corpusState }))

const planScope = vi.fn()
vi.mock('../api/planScope', () => ({
  fetchPlanScope: (...args: unknown[]) => planScope(...args),
  PlanScopeFetchError: class extends Error {},
}))

const { usePlansLens } = await import('./usePlansLens')

const row = (id: string, type: string, fields: Record<string, unknown>) => ({ id, type, title: `${id} title`, fields })

let host: HTMLDivElement
let root: Root
let seen: ReturnType<typeof usePlansLens> | null = null

function Probe() {
  seen = usePlansLens()
  return null
}

async function mount() {
  await act(async () => {
    root.render(<Probe />)
  })
}

beforeEach(() => {
  seen = null
  planScope.mockReset()
  planScope.mockResolvedValue({ times: new Map(), truncated: false, generatedAt: null, totalPlans: 0 })
  corpusState = {
    rows: [
      row('ENC-PLN-1', 'plan', { project_id: 'enceladus', status: 'started', objectives_set: ['ENC-TSK-A'] }),
      row('ENC-TSK-A', 'task', { project_id: 'enceladus', status: 'closed', parent: 'ENC-PLN-1', wave: 'W1', checkout_state: 'checked_in' }),
      row('DOC-1', 'document', { project_id: 'enceladus' }),
    ],
    status: 'ready',
    lastSeededAt: '2026-11-19T00:00:00Z',
    staleNotice: null,
    error: null,
    refresh: vi.fn(async () => {}),
  }
  host = document.createElement('div')
  document.body.appendChild(host)
  root = createRoot(host)
})

afterEach(async () => {
  await act(async () => root.unmount())
  host.remove()
})

describe('usePlansLens (ENC-TSK-S98-0C)', () => {
  it('maps only plan and task rows, carrying the structure the resolver needs', async () => {
    await mount()
    const rows = seen!.rows as PlansRow[]
    expect(rows.map((r) => r.item_id)).toEqual(['ENC-PLN-1', 'ENC-TSK-A'])
    // A document is in the corpus and is not the Plans page's business.
    expect(rows.some((r) => r.item_id === 'DOC-1')).toBe(false)
    const task = rows.find((r) => r.item_id === 'ENC-TSK-A')!
    expect(task.parent).toBe('ENC-PLN-1')
    expect(task.wave).toBe('W1')
    expect(task.status).toBe('closed')
    const plan = rows.find((r) => r.item_id === 'ENC-PLN-1')!
    expect(plan.objectives_set).toEqual(['ENC-TSK-A'])
  })

  it('draws structure before the plan-scoped read lands, then overlays the time scale', async () => {
    // A read that never resolves: structure must still be there.
    planScope.mockReturnValue(new Promise(() => {}))
    await mount()
    const before = seen!.rows as PlansRow[]
    expect(before).toHaveLength(2)
    expect(before.find((r) => r.item_id === 'ENC-TSK-A')!.first_checked_out_at ?? null).toBeNull()
  })

  it('overlays created_at, first_checked_out_at and closed_at onto the matching rows', async () => {
    planScope.mockResolvedValue({
      times: new Map([
        ['ENC-PLN-1', { created_at: '2026-11-01T00:00:00Z' }],
        ['ENC-TSK-A', { created_at: '2026-11-02T00:00:00Z', first_checked_out_at: '2026-11-03T00:00:00Z', closed_at: '2026-11-04T00:00:00Z' }],
      ]),
      truncated: false,
      generatedAt: '2026-11-19T00:00:00Z',
      totalPlans: 1,
    })
    await mount()
    const task = (seen!.rows as PlansRow[]).find((r) => r.item_id === 'ENC-TSK-A')!
    expect(task.created_at).toBe('2026-11-02T00:00:00Z')
    expect(task.first_checked_out_at).toBe('2026-11-03T00:00:00Z')
    expect(task.closed_at).toBe('2026-11-04T00:00:00Z')
    const plan = (seen!.rows as PlansRow[]).find((r) => r.item_id === 'ENC-PLN-1')!
    expect(plan.created_at).toBe('2026-11-01T00:00:00Z')
  })

  /** ENC-TSK-T05 AC-4: one request per Plans page open, and none from any other route. */
  it('asks for the plan scope exactly once, even when the corpus notifies again', async () => {
    await mount()
    expect(planScope).toHaveBeenCalledTimes(1)
    // A corpus notification re-renders the hook; it must not re-request.
    await act(async () => {
      corpusState = { ...corpusState, rows: [...corpusState.rows] }
      root.render(<Probe />)
    })
    expect(planScope).toHaveBeenCalledTimes(1)
  })

  it('a failed plan-scope read leaves the page usable: structure stands, the error is reported', async () => {
    planScope.mockRejectedValue(new Error('plan scope exploded'))
    await mount()
    expect(seen!.rows).toHaveLength(2)
    expect(seen!.error).toBe('plan scope exploded')
  })

  it('reports corpus freshness, not a manual-refresh stamp (section 5.8)', async () => {
    await mount()
    expect(seen!.asOf).toBe('2026-11-19T00:00:00Z')
    expect(seen!.stale).toBe(false)
  })
})
