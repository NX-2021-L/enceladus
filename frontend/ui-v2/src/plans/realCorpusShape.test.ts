import { describe, expect, it } from 'vitest'
import { buildPlanView, type PlansRow } from './planView'
import { selectPlans } from './lens/selectPlans'

/**
 * Integration check against the CURRENT corpus row shape, as observed live on gamma 2026-11-19.
 *
 * This exists because the page showed "0 tree tasks in 0 waves, 0 closed" on every card, and the lens unit tests
 * could not have caught it: they feed hand-made rows that already carry objectives_set, while the client was
 * holding rows from before W2.1 widened the row. ENC-TSK-T13 fixes the delivery of the new shape; this pins the
 * other half -- that rows OF that shape actually resolve into a tree.
 *
 * The fixture mirrors three real gamma plans rather than quoting them in full: ENC-PLN-047 (4 objectives),
 * MOD-PLN-001 (3) and ENC-PLN-049 (8). The property that matters, and that surprised me, is that every one of
 * their 15 objective rows carries NO parent and NO wave -- the trees are entirely flat, and membership comes from
 * objectives_set alone. The three lifecycle timestamps come from the plan-scoped read, as D-26 requires, and all
 * 18 captured rows had them.
 */

const T = (id: string, status: string, times: { created: string; firstOut?: string; closed?: string }): PlansRow => ({
  item_id: id,
  record_type: 'task',
  title: `${id} title`,
  project_id: 'enceladus',
  status,
  checkout_state: 'checked_in',
  created_at: times.created,
  ...(times.firstOut ? { first_checked_out_at: times.firstOut } : {}),
  ...(times.closed ? { closed_at: times.closed } : {}),
})

const PLAN: PlansRow = {
  item_id: 'ENC-PLN-047',
  record_type: 'plan',
  title: '02-compute IAM Remediation',
  project_id: 'enceladus',
  status: 'started',
  checkout_state: 'checked_in',
  created_at: '2026-06-01T00:00:00Z',
  objectives_set: ['ENC-TSK-G95', 'ENC-TSK-H01', 'ENC-TSK-H02', 'ENC-TSK-H03'],
}

const ROWS: PlansRow[] = [
  PLAN,
  T('ENC-TSK-G95', 'merged_main', { created: '2026-06-02T00:00:00Z', firstOut: '2026-06-03T00:00:00Z' }),
  T('ENC-TSK-H01', 'closed', { created: '2026-06-02T01:00:00Z', firstOut: '2026-06-03T01:00:00Z', closed: '2026-06-17T03:26:20Z' }),
  T('ENC-TSK-H02', 'closed', { created: '2026-06-02T02:00:00Z', firstOut: '2026-06-03T02:00:00Z', closed: '2026-06-18T00:00:00Z' }),
  T('ENC-TSK-H03', 'open', { created: '2026-06-02T03:00:00Z' }),
]

const NOW = Date.parse('2026-11-19T22:00:00Z')

describe('the lens resolves rows of the shape gamma actually serves', () => {
  it('selects the plan from a live-shaped corpus', () => {
    const selection = selectPlans(ROWS, { project: '', count: 20 })
    expect(selection.plans.map((p) => p.item_id)).toContain('ENC-PLN-047')
  })

  /** The regression that shipped: a plan whose objectives are present must NOT read "0 tree tasks". */
  it('builds a non-empty tree from objectives_set alone, with no parent and no wave on any row', () => {
    expect(ROWS.filter((r) => r.parent).length).toBe(0)
    expect(ROWS.filter((r) => r.wave).length).toBe(0)

    const view = buildPlanView(PLAN, ROWS, NOW)
    const treeTaskIds = new Set(view.waves.flatMap((w) => w.tasks.map((t) => t.id)))

    expect(view.stats.nTasks).toBe(4)
    expect(view.stats.nWaves).toBe(1)
    expect(treeTaskIds.size).toBe(4)
    for (const id of PLAN.objectives_set ?? []) expect(treeTaskIds.has(id)).toBe(true)
  })

  /** Flat objectives have no wave label and no wave number in the title, so they belong to the Unassigned group. */
  it('puts flat objectives in a single Unassigned wave rather than dropping them', () => {
    const view = buildPlanView(PLAN, ROWS, NOW)
    expect(view.waves.length).toBe(1)
    const only = view.waves[0]!
    expect(only.unassigned).toBe(true)
    expect(only.tasks.map((t) => t.id)).toEqual(
      expect.arrayContaining(['ENC-TSK-G95', 'ENC-TSK-H01', 'ENC-TSK-H02', 'ENC-TSK-H03']),
    )
  })

  /** Two of the four are closed; the card's "N closed" must reflect that, not zero. */
  it('counts the closed objectives', () => {
    const view = buildPlanView(PLAN, ROWS, NOW)
    expect(view.stats.nClosed).toBe(2)
    expect(view.waves[0]!.closed).toBe(2)
    expect(view.waves[0]!.total).toBe(4)
  })
})
