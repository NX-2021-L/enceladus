import { act, useEffect } from 'react'
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
  storageFault?: string | null
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
/**
 * The probe publishes through a stable outer box rather than reassigning an outer binding: the React Compiler lint
 * rejects a component that writes to a variable declared outside it, and a box keeps every assertion below unchanged.
 */
/**
 * The probe publishes through a module-level setter called from an effect, not by assigning an outer binding from the
 * component body: react-hooks/immutability and the React Compiler lint both reject the latter. Every assertion below
 * is unchanged -- `act()` flushes the effect, so the value is in place by the time the test reads it.
 */
let seen: ReturnType<typeof usePlansLens> | null = null
const publish = (v: ReturnType<typeof usePlansLens>): void => {
  seen = v
}

function Probe() {
  const lens = usePlansLens()
  useEffect(() => {
    publish(lens)
  }, [lens])
  return null
}

async function mount() {
  await act(async () => {
    root.render(<Probe />)
  })
}

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
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
    storageFault: null,
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

  /**
   * Found on gamma: /feed/plan-scope 404'd (its API Gateway route had not been deployed there) and the page replaced
   * 60 plans with "Plans could not be loaded". PlansPage treats `error` as fatal, so the time-scale failure must
   * never travel in it.
   */
  it('a failed plan-scope read loses the time scale, NOT the page', async () => {
    planScope.mockRejectedValue(new Error('Failed to read plan scope (404)'))
    await mount()
    expect(seen!.rows).toHaveLength(2)
    // Structure is intact and the page is not in its fatal state.
    expect(seen!.error).toBeNull()
    expect(seen!.timeScaleError).toBe('Failed to read plan scope (404)')
  })

  it('a corpus failure IS fatal: there is nothing to draw', async () => {
    corpusState = { ...corpusState, rows: [], error: 'corpus unreachable' }
    await mount()
    expect(seen!.error).toBe('corpus unreachable')
  })

  /**
   * The refresh control must be AUTHORITATIVE. Without `{ seed: true }` the kit takes its heal-only branch while
   * the stored seed is younger than seedMaxAgeMs (24h, W2.5), so it issues /feed/delta and never /feed/corpus --
   * and a delta only returns rows whose version_seq moved. W2.1 widened the row SHAPE, so a plan whose record has
   * not changed since keeps its pre-W2.1 fields and resolves to "0 tree tasks in 0 waves" forever. Observed on
   * gamma, where the page's own refresh could not repair it.
   */
  it('refresh forces a full re-seed, not a delta heal', async () => {
    await mount()
    seen!.refresh()
    expect(corpusState.refresh).toHaveBeenCalledWith({ seed: true })
  })

  /**
   * ENC-TSK-T16 W7-F1. A corpus store that could not be opened used to hang the whole app silently; @io-kit/search
   * 1.1.3 bounds it and reports storageFault instead. It must NOT travel in `error`, which PlansPage treats as
   * fatal -- the rows still arrive over the network, so every card draws and only the warm start is lost.
   */
  it('passes a storage fault through without making the page fatal', async () => {
    corpusState = { ...corpusState, storageFault: 'corpus storage read timed out after 5000ms' }
    await mount()
    expect(seen!.storageFault).toBe('corpus storage read timed out after 5000ms')
    expect(seen!.error).toBeNull()
    expect(seen!.rows).toHaveLength(2)
  })

  it('reports no storage fault when the device cache is healthy', async () => {
    await mount()
    expect(seen!.storageFault).toBeNull()
  })

  it('reports corpus freshness, not a manual-refresh stamp (section 5.8)', async () => {
    await mount()
    expect(seen!.asOf).toBe('2026-11-19T00:00:00Z')
    expect(seen!.stale).toBe(false)
  })
})

/**
 * ENC-TSK-T22 (ENC-ISS-922). The seeded corpus row carries none of the three lifecycle timestamps -- ruling D-26 took
 * them off it. A LIVE row can carry them: ENC-TSK-S97-0B puts recordCreatedAt, recordFirstCheckedOutAt and
 * recordClosedAt on the /feed/updates event and the kit's mergeHeadline writes them into IndexRow.fields. Before this
 * the adapter read only created_at, so those arrived and were dropped, and the plan-scoped read -- which runs ONCE per
 * page open -- was the lens's only route to a stamp. That is what stopped criterion 8 firing on an open page.
 */
describe('live lifecycle stamps from the corpus row (ENC-TSK-T22, ENC-ISS-922)', () => {
  const liveRow = () =>
    row('ENC-TSK-LIVE', 'task', {
      project_id: 'enceladus',
      status: 'in-progress',
      parent: 'ENC-PLN-1',
      checkout_state: 'checked_out',
      first_checked_out_at: '2026-11-20T03:39:52Z',
      closed_at: '2026-11-20T04:00:00Z',
    })

  it('carries first_checked_out_at and closed_at through when the plan-scope map has no entry for the row', async () => {
    corpusState.rows = [...corpusState.rows, liveRow()]
    planScope.mockResolvedValue({ times: new Map(), truncated: false, generatedAt: null, totalPlans: 0 })
    await mount()
    const live = (seen!.rows as PlansRow[]).find((r) => r.item_id === 'ENC-TSK-LIVE')!
    expect(live.first_checked_out_at).toBe('2026-11-20T03:39:52Z')
    expect(live.closed_at).toBe('2026-11-20T04:00:00Z')
  })

  it('lets the plan-scope value win when both are present', async () => {
    corpusState.rows = [...corpusState.rows, liveRow()]
    planScope.mockResolvedValue({
      times: new Map([['ENC-TSK-LIVE', { first_checked_out_at: '2026-11-20T01:00:00Z', closed_at: '2026-11-20T02:00:00Z' }]]),
      truncated: false,
      generatedAt: null,
      totalPlans: 0,
    })
    await mount()
    const live = (seen!.rows as PlansRow[]).find((r) => r.item_id === 'ENC-TSK-LIVE')!
    expect(live.first_checked_out_at).toBe('2026-11-20T01:00:00Z')
    expect(live.closed_at).toBe('2026-11-20T02:00:00Z')
  })

  it('falls back to the row value for a field the plan-scope entry omits', async () => {
    corpusState.rows = [...corpusState.rows, liveRow()]
    planScope.mockResolvedValue({
      times: new Map([['ENC-TSK-LIVE', { created_at: '2026-11-18T00:00:00Z' }]]),
      truncated: false,
      generatedAt: null,
      totalPlans: 0,
    })
    await mount()
    const live = (seen!.rows as PlansRow[]).find((r) => r.item_id === 'ENC-TSK-LIVE')!
    expect(live.created_at).toBe('2026-11-18T00:00:00Z')
    // The entry said nothing about these two, so the live row's own values must survive rather than be nulled.
    expect(live.first_checked_out_at).toBe('2026-11-20T03:39:52Z')
    expect(live.closed_at).toBe('2026-11-20T04:00:00Z')
  })
})
