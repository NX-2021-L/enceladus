import { beforeEach, describe, expect, it } from 'vitest'
import { buildAffectedIndex, planSignature, planViewsOf, resetPlanViewCache, rowSignature } from './planViews'
import type { PlansRow } from './planView'

/**
 * ENC-TSK-S99-0B (ENC-PLN-108 W4.2): only the plans whose rows changed are rebuilt.
 *
 * Rebuild is observed by OBJECT IDENTITY rather than by a spy: a cache hit returns the previous `PlanView`, so
 * `toBe` is a direct statement about whether the card was recomputed. No mocking, and nothing to drift.
 */

const NOW = Date.parse('2026-11-19T22:00:00Z')

const task = (id: string, extra: Partial<PlansRow> = {}): PlansRow => ({
  item_id: id,
  record_type: 'task',
  title: `${id} title`,
  project_id: 'enceladus',
  status: 'open',
  checkout_state: 'checked_in',
  created_at: '2026-11-01T00:00:00Z',
  ...extra,
})

const plan = (id: string, objectives: string[]): PlansRow => ({
  item_id: id,
  record_type: 'plan',
  title: `${id} title`,
  project_id: 'enceladus',
  status: 'started',
  checkout_state: 'checked_in',
  created_at: '2026-10-01T00:00:00Z',
  objectives_set: objectives,
})

/** Two plans, one with a child below its objective, plus a task that belongs to neither. */
const corpus = (): PlansRow[] => [
  plan('ENC-PLN-1', ['ENC-TSK-A', 'ENC-TSK-B']),
  task('ENC-TSK-A', { wave: 'W1' }),
  task('ENC-TSK-B', { wave: 'W1' }),
  task('ENC-TSK-A1', { parent: 'ENC-TSK-A' }),
  plan('ENC-PLN-2', ['ENC-TSK-C']),
  task('ENC-TSK-C', { wave: 'W1' }),
  task('ENC-TSK-ELSEWHERE', { project_id: 'other' }),
]

const plansOf = (rows: readonly PlansRow[]) => rows.filter((r) => r.record_type === 'plan')

beforeEach(() => {
  resetPlanViewCache()
})

describe('rowSignature covers exactly what the lens reads', () => {
  const base = task('ENC-TSK-A', { parent: 'P', wave: 'W1', first_checked_out_at: '2026-11-02T00:00:00Z', closed_at: null })

  /** Every field buildPlanView, resolveWaves or waveState reads must move the signature. */
  it.each([
    ['title', { title: 'other' }],
    ['status', { status: 'closed' }],
    ['checkout_state', { checkout_state: 'checked_out' }],
    ['parent', { parent: 'Q' }],
    ['wave', { wave: 'W2' }],
    ['objectives_set', { objectives_set: ['X'] }],
    ['created_at', { created_at: '2026-11-09T00:00:00Z' }],
    ['first_checked_out_at', { first_checked_out_at: '2026-11-09T00:00:00Z' }],
    ['closed_at', { closed_at: '2026-11-09T00:00:00Z' }],
    ['project_id', { project_id: 'other' }],
    ['record_type', { record_type: 'plan' }],
  ])('a change to %s changes the signature', (_name, patch) => {
    expect(rowSignature({ ...base, ...(patch as Partial<PlansRow>) })).not.toBe(rowSignature(base))
  })

  /** And a field the lens does not read must NOT invalidate a card. */
  it('ignores a corpus field the lens never reads', () => {
    const withExtra = { ...base, priority: 'P0', tags: ['x'] } as unknown as PlansRow
    expect(rowSignature(withExtra)).toBe(rowSignature(base))
  })
})

describe('buildAffectedIndex', () => {
  it('gives a plan its objectives and their descendants, and nothing else', () => {
    const index = buildAffectedIndex(corpus())
    expect(index.affects.get('ENC-PLN-1')).toEqual(['ENC-PLN-1', 'ENC-TSK-A', 'ENC-TSK-A1', 'ENC-TSK-B'])
    expect(index.affects.get('ENC-PLN-2')).toEqual(['ENC-PLN-2', 'ENC-TSK-C'])
  })

  it('terminates on a parent cycle', () => {
    const rows = [plan('P', ['A']), task('A', { parent: 'B' }), task('B', { parent: 'A' })]
    expect(buildAffectedIndex(rows).affects.get('P')).toEqual(['A', 'B', 'P'])
  })

  it('moves a plan signature when one of its own rows moves, and not when a stranger does', () => {
    const rows = corpus()
    const before = planSignature('ENC-PLN-1', buildAffectedIndex(rows), NOW)

    const stranger = rows.map((r) => (r.item_id === 'ENC-TSK-ELSEWHERE' ? { ...r, status: 'closed' } : r))
    expect(planSignature('ENC-PLN-1', buildAffectedIndex(stranger), NOW)).toBe(before)

    const mine = rows.map((r) => (r.item_id === 'ENC-TSK-A1' ? { ...r, status: 'closed' } : r))
    expect(planSignature('ENC-PLN-1', buildAffectedIndex(mine), NOW)).not.toBe(before)
  })

  /** An objective that is not in the corpus is the plan header's `missing` count, so its absence must count. */
  it('counts an objective with no row, so its arrival rebuilds the card', () => {
    const without = [plan('P', ['A', 'GHOST']), task('A')]
    const with_ = [...without, task('GHOST')]
    expect(planSignature('P', buildAffectedIndex(with_), NOW)).not.toBe(planSignature('P', buildAffectedIndex(without), NOW))
  })
})

describe('planViewsOf rebuilds only what changed', () => {
  it('returns the same card objects when nothing changed', () => {
    const rows = corpus()
    const first = planViewsOf(plansOf(rows), rows, NOW)
    // A fresh array of equal rows: this is what a heal that changed nothing looks like.
    const rows2 = corpus()
    const second = planViewsOf(plansOf(rows2), rows2, NOW)
    expect(second[0]).toBe(first[0])
    expect(second[1]).toBe(first[1])
  })

  it('rebuilds the touched plan and leaves the other alone', () => {
    const rows = corpus()
    const first = planViewsOf(plansOf(rows), rows, NOW)

    const rows2 = corpus().map((r) => (r.item_id === 'ENC-TSK-B' ? { ...r, status: 'closed', closed_at: '2026-11-18T00:00:00Z' } : r))
    const second = planViewsOf(plansOf(rows2), rows2, NOW)

    expect(second[0]).not.toBe(first[0])
    expect(second[1]).toBe(first[1])
    // And the rebuild is a real one, not just a new object.
    expect(second[0]!.stats.nClosed).toBe(1)
    expect(first[0]!.stats.nClosed).toBe(0)
  })

  /**
   * The case that rules out the obvious implementation. A live AppSync event is applied as a headline overlay and
   * KEEPS the row's existing version token while changing `status` (see corpusSource.applyEvent). A cache keyed on
   * `version` would swallow exactly the update the page exists to show -- the live checkout of criterion 4 -- and a
   * page fed by events would then draw differently from a cold load, which is criterion 14.
   */
  it('rebuilds on a live checkout that does not move the row version', () => {
    const rows = corpus()
    const first = planViewsOf(plansOf(rows), rows, NOW)

    // What a live checkout event actually carries: status and checkout_state, under the SAME version token. It
    // carries no first_checked_out_at, because D-26 keeps that off the corpus entirely -- so until the next
    // plan-scope read the visible effect is the status pill standing in for the bar (invariant 6).
    const checkedOut = corpus().map((r) =>
      r.item_id === 'ENC-TSK-B'
        ? ({ ...r, status: 'in-progress', checkout_state: 'checked_out', version: '12345' } as PlansRow)
        : ({ ...r, version: '12345' } as PlansRow),
    )
    const second = planViewsOf(plansOf(checkedOut), checkedOut, NOW)

    expect(second[0]).not.toBe(first[0])
    const taskBefore = first[0]!.waves.flatMap((w) => w.tasks).find((t) => t.id === 'ENC-TSK-B')!
    const taskAfter = second[0]!.waves.flatMap((w) => w.tasks).find((t) => t.id === 'ENC-TSK-B')!
    expect(taskBefore.showStatusPill).toBe(false)
    expect(taskAfter.showStatusPill).toBe(true)
    expect(taskAfter.role).toBe('active')
  })

  it('rebuilds every card when the now edge moves', () => {
    const rows = corpus()
    const first = planViewsOf(plansOf(rows), rows, NOW)
    const second = planViewsOf(plansOf(rows), rows, NOW + 60_000)
    expect(second[0]).not.toBe(first[0])
    expect(second[1]).not.toBe(first[1])
  })

  /** A cache hit must be indistinguishable from a rebuild: same inputs, same card (criterion 14 in the small). */
  it('a cache hit equals what a cold build would have produced', () => {
    const rows = corpus()
    const warm = planViewsOf(plansOf(rows), rows, NOW)[0]!
    resetPlanViewCache()
    const cold = planViewsOf(plansOf(rows), rows, NOW)[0]!
    expect(JSON.stringify(warm, replacer)).toBe(JSON.stringify(cold, replacer))
  })
})

/** `ariaLabel` is a function; compare its output rather than dropping it. */
const replacer = (_k: string, v: unknown) => (typeof v === 'function' ? (v as (open: boolean) => string)(true) : v)
