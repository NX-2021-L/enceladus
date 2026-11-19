import { describe, expect, it } from 'vitest'
import { F6, F7, F10, task, type FixtureRow } from './__fixtures__'
import {
  LENS_CHANGE_TYPES,
  diff,
  snapshotPlan,
  type LensChange,
  type LensSnapshot,
  type PlanSnapshot,
  type SnapshotRow,
  type TaskSnapshot,
  type WaveSnapshot,
} from './diff'

const tk = (id: string, status: string | null = 'open', checkedOut = false): TaskSnapshot => ({ id, status, checkedOut })
const wv = (key: string, members: string[], state: WaveSnapshot['state'] = 'todo', hot = false): WaveSnapshot => ({ key, state, hot, members })
const plan = (id: string, waves: WaveSnapshot[], tasks: TaskSnapshot[]): PlanSnapshot => ({ id, waves, tasks })

const base = (): PlanSnapshot =>
  plan('P1', [wv('W1', ['a', 'b', 'c'])], [tk('a'), tk('b'), tk('c')])

describe('diff', () => {
  it('equal snapshots give an empty change set', () => {
    const s: LensSnapshot = [base()]
    expect(diff(s, s)).toEqual([])
    expect(diff([], [])).toEqual([])
  })

  it('names exactly the eight change types of section 5.6', () => {
    expect([...LENS_CHANGE_TYPES]).toEqual(['plan-added', 'task-added', 'checkout', 'close', 'reopen', 'wave-state-change', 'wave-hot-change', 'reorder'])
  })

  it('plan added: a new plan is one event, and its tasks and waves raise none of their own', () => {
    expect(diff([base()], [plan('P2', [wv('W1', ['x'], 'active', true)], [tk('x', 'in-progress', true)]), base()])).toEqual([
      { type: 'plan-added', planId: 'P2' },
    ])
    expect(diff([], [base()])).toEqual([{ type: 'plan-added', planId: 'P1' }])
  })

  it('task added: carries the plan and the wave that now holds it, or null for an Unassigned row or a wave parent', () => {
    const next = plan('P1', [wv('W1', ['a', 'b', 'c', 'd'])], [tk('a'), tk('b'), tk('c'), tk('d'), tk('stray')])
    expect(diff([base()], [next])).toEqual([
      { type: 'task-added', planId: 'P1', taskId: 'd', waveKey: 'W1' },
      { type: 'task-added', planId: 'P1', taskId: 'stray', waveKey: null },
    ])
  })

  it('checkout: a task becomes checked out', () => {
    const next = plan('P1', base().waves.slice(), [tk('a'), tk('b', 'in-progress', true), tk('c')])
    expect(diff([base()], [next])).toEqual([{ type: 'checkout', planId: 'P1', taskId: 'b' }])
  })

  it('close: a task becomes closed', () => {
    const before = plan('P1', [wv('W1', ['a'])], [tk('a', 'in-progress', true)])
    const after = plan('P1', [wv('W1', ['a'])], [tk('a', 'closed', true)])
    expect(diff([before], [after])).toEqual([{ type: 'close', planId: 'P1', taskId: 'a' }])
  })

  it('a task that goes from open to closed in one step is both a checkout and a close, in that order', () => {
    const before = plan('P1', [wv('W1', ['a'])], [tk('a')])
    const after = plan('P1', [wv('W1', ['a'])], [tk('a', 'closed', true)])
    expect(diff([before], [after]).map((c) => c.type)).toEqual(['checkout', 'close'])
  })

  it('a task closed without any checkout stamp is a close alone', () => {
    const before = plan('P1', [wv('W1', ['a'])], [tk('a')])
    const after = plan('P1', [wv('W1', ['a'])], [tk('a', 'closed', false)])
    expect(diff([before], [after])).toEqual([{ type: 'close', planId: 'P1', taskId: 'a' }])
  })

  it('reopen: a closed task re-enters, and it is not a second checkout', () => {
    const before = plan('P1', [wv('W1', ['a'])], [tk('a', 'closed', true)])
    const after = plan('P1', [wv('W1', ['a'])], [tk('a', 'in-progress', true)])
    expect(diff([before], [after])).toEqual([{ type: 'reopen', planId: 'P1', taskId: 'a' }])
  })

  it('superseded is not a close', () => {
    const before = plan('P1', [wv('W1', ['a'])], [tk('a', 'open')])
    const after = plan('P1', [wv('W1', ['a'])], [tk('a', 'superseded')])
    expect(diff([before], [after])).toEqual([])
  })

  it('wave state change carries from and to', () => {
    const before = plan('P1', [wv('W1', ['a'], 'todo')], [tk('a')])
    const after = plan('P1', [wv('W1', ['a'], 'active')], [tk('a')])
    expect(diff([before], [after])).toEqual([{ type: 'wave-state-change', planId: 'P1', waveKey: 'W1', from: 'todo', to: 'active' }])
  })

  it('wave hot change carries the new hotness, both ways', () => {
    const cold = plan('P1', [wv('W1', ['a'], 'active', false)], [tk('a')])
    const hot = plan('P1', [wv('W1', ['a'], 'active', true)], [tk('a')])
    expect(diff([cold], [hot])).toEqual([{ type: 'wave-hot-change', planId: 'P1', waveKey: 'W1', hot: true }])
    expect(diff([hot], [cold])).toEqual([{ type: 'wave-hot-change', planId: 'P1', waveKey: 'W1', hot: false }])
  })

  it('reorder: carries the wave and its new order', () => {
    const after = plan('P1', [wv('W1', ['c', 'a', 'b'])], base().tasks.slice())
    expect(diff([base()], [after])).toEqual([{ type: 'reorder', planId: 'P1', waveKey: 'W1', order: ['c', 'a', 'b'] }])
  })

  it('a row that joined or left a wave is not a reorder of the rows that stayed', () => {
    const joined = plan('P1', [wv('W1', ['a', 'x', 'b', 'c'])], [...base().tasks, tk('x')])
    expect(diff([base()], [joined]).map((c) => c.type)).toEqual(['task-added'])
    const left = plan('P1', [wv('W1', ['a', 'c'])], base().tasks.slice())
    expect(diff([base()], [left])).toEqual([])
  })

  it('a wave that exists only in next raises no wave event, and a wave that vanished raises none either', () => {
    const next = plan('P1', [wv('W1', ['a', 'b', 'c']), wv('W2', ['z'], 'active', true)], [...base().tasks, tk('z', 'in-progress', true)])
    expect(diff([base()], [next]).map((c) => c.type)).toEqual(['task-added'])
    expect(diff([next], [base()])).toEqual([])
  })

  it('a plan or a task that disappears raises no change: nothing animates it', () => {
    expect(diff([base()], [])).toEqual([])
    expect(diff([base()], [plan('P1', [wv('W1', ['a'])], [tk('a')])])).toEqual([])
  })

  it('orders events deterministically: plans in next order, task events, then each wave\'s events', () => {
    const before: LensSnapshot = [
      plan('P1', [wv('W1', ['a', 'b'], 'todo', false)], [tk('a'), tk('b')]),
      plan('P2', [wv('W1', ['c'], 'active', true)], [tk('c', 'in-progress', true)]),
    ]
    const after: LensSnapshot = [
      plan('P2', [wv('W1', ['c'], 'done', false)], [tk('c', 'closed', true)]),
      plan('P1', [wv('W1', ['b', 'a'], 'active', true)], [tk('a', 'in-progress', true), tk('b')]),
      plan('P3', [], []),
    ]
    const types = diff(before, after).map((c) => `${c.planId}:${c.type}`)
    expect(types).toEqual([
      'P2:close',
      'P2:wave-state-change',
      'P2:wave-hot-change',
      'P1:checkout',
      'P1:wave-state-change',
      'P1:wave-hot-change',
      'P1:reorder',
      'P3:plan-added',
    ])
  })

  it('does not mutate its inputs', () => {
    const a: LensSnapshot = [base()]
    const b: LensSnapshot = [plan('P1', [wv('W1', ['c', 'b', 'a'], 'active', true)], [tk('a', 'closed', true), tk('b'), tk('c')])]
    const before = JSON.stringify([a, b])
    diff(a, b)
    expect(JSON.stringify([a, b])).toBe(before)
  })
})

describe('snapshotPlan feeding diff: a plan resolved from rows, then a change, then the typed change set', () => {
  const CO = '2026-11-19T08:00:00Z'
  const rowsOf = (f: { rows: readonly FixtureRow[] }, patch: Record<string, Partial<SnapshotRow>> = {}): SnapshotRow[] =>
    f.rows.map((r) => ({ ...r, ...patch[r.item_id] }))
  const snap = (f: { plan_id: string; objectives: string[]; rows: readonly FixtureRow[] }, patch: Record<string, Partial<SnapshotRow>> = {}) =>
    snapshotPlan({ item_id: f.plan_id, objectives_set: f.objectives }, rowsOf(f, patch))

  it('snapshots every wave with its state, hotness and members, and every task row of the plan', () => {
    const s = snap(F7)
    expect(s.id).toBe('FIN-PLN-009')
    expect(s.waves.map((w) => [w.key, w.state, w.hot])).toEqual([['W0', 'todo', false], ['W1', 'todo', false], ['W2', 'todo', false], ['W3', 'todo', false]])
    expect(s.tasks.map((t) => t.id)).toEqual([...F7.expected.waves.flatMap((w) => w.members), ...F7.expected.unassigned])
  })

  it('a checkout in a wave makes it active and hot, and says so', () => {
    const before = snap(F7)
    const after = snap(F7, { 'FIN-TSK-266': { status: 'in-progress', first_checked_out_at: CO } })
    expect(diff([before], [after])).toEqual<LensChange[]>([
      { type: 'checkout', planId: 'FIN-PLN-009', taskId: 'FIN-TSK-266' },
      { type: 'wave-state-change', planId: 'FIN-PLN-009', waveKey: 'W3', from: 'todo', to: 'active' },
      { type: 'wave-hot-change', planId: 'FIN-PLN-009', waveKey: 'W3', hot: true },
    ])
  })

  it('closing the only member of a parentless wave ends it: done, no longer hot', () => {
    const working = snap(F7, { 'FIN-TSK-266': { status: 'in-progress', first_checked_out_at: CO } })
    const finished = snap(F7, { 'FIN-TSK-266': { status: 'closed', first_checked_out_at: CO } })
    expect(diff([working], [finished])).toEqual<LensChange[]>([
      { type: 'close', planId: 'FIN-PLN-009', taskId: 'FIN-TSK-266' },
      { type: 'wave-state-change', planId: 'FIN-PLN-009', waveKey: 'W3', from: 'active', to: 'done' },
      { type: 'wave-hot-change', planId: 'FIN-PLN-009', waveKey: 'W3', hot: false },
    ])
  })

  it('regression: reopening that task redraws the wave as active and hot (invariant 7)', () => {
    const finished = snap(F7, { 'FIN-TSK-266': { status: 'closed', first_checked_out_at: CO } })
    const reopened = snap(F7, { 'FIN-TSK-266': { status: 'in-progress', first_checked_out_at: CO } })
    expect(diff([finished], [reopened])).toEqual<LensChange[]>([
      { type: 'reopen', planId: 'FIN-PLN-009', taskId: 'FIN-TSK-266' },
      { type: 'wave-state-change', planId: 'FIN-PLN-009', waveKey: 'W3', from: 'done', to: 'active' },
      { type: 'wave-hot-change', planId: 'FIN-PLN-009', waveKey: 'W3', hot: true },
    ])
  })

  it('the parent closing resolves a parent wave, and reopening the parent returns it to active', () => {
    const members = { 'INT-TSK-643-0A': { status: 'closed', first_checked_out_at: CO } }
    const settling = snap(F10, { ...members, 'INT-TSK-643': { status: 'in-progress', first_checked_out_at: CO } })
    const closedParent = snap(F10, { ...members, 'INT-TSK-643': { status: 'closed', first_checked_out_at: CO } })
    expect(settling.waves.find((w) => w.key === 'W3')).toMatchObject({ state: 'active', hot: false })
    expect(diff([settling], [closedParent])).toEqual<LensChange[]>([
      { type: 'close', planId: 'INT-PLN-031', taskId: 'INT-TSK-643' },
      { type: 'wave-state-change', planId: 'INT-PLN-031', waveKey: 'W3', from: 'active', to: 'done' },
    ])
    expect(diff([closedParent], [settling])).toEqual<LensChange[]>([
      { type: 'reopen', planId: 'INT-PLN-031', taskId: 'INT-TSK-643' },
      { type: 'wave-state-change', planId: 'INT-PLN-031', waveKey: 'W3', from: 'done', to: 'active' },
    ])
  })

  it('a task added to a plan lands in the wave its parent pointer names, and is announced with that wave', () => {
    const before = snap(F6)
    const after = snapshotPlan({ item_id: F6.plan_id, objectives_set: [...F6.objectives, 'ENC-TSK-S90'] }, [...rowsOf(F6), task('ENC-TSK-S90', 'W2-C Late addition')])
    expect(diff([before], [after])).toEqual<LensChange[]>([{ type: 'task-added', planId: 'ENC-PLN-107', taskId: 'ENC-TSK-S90', waveKey: 'W2' }])
  })

  it('moving an objective inside a wave is a reorder of that wave only', () => {
    const before = snap(F6)
    const swapped = [...F6.objectives]
    ;[swapped[1], swapped[2]] = [swapped[2] as string, swapped[1] as string]
    // S82 and S83 carry subordinals A and B, which keep W2 in A-then-B order whatever objectives_set says (R-1), so no reorder.
    const afterSorted = snapshotPlan({ item_id: F6.plan_id, objectives_set: swapped }, rowsOf(F6))
    expect(diff([before], [afterSorted])).toEqual([])
    // Without subordinals the objective order is the order, and swapping two objectives moves rows.
    const flat = (order: string[]) =>
      snapshotPlan({ item_id: 'X', objectives_set: order }, [task('A', 'W1 one'), task('B', 'W1 two'), task('C', 'W1 three')])
    expect(diff([flat(['A', 'B', 'C'])], [flat(['A', 'C', 'B'])])).toEqual<LensChange[]>([
      { type: 'reorder', planId: 'X', waveKey: 'W1', order: ['A', 'C', 'B'] },
    ])
  })

  it('a task that leaves Unassigned for a wave is not a new task, and a regrouping is not one of the eight change types', () => {
    const before = snap(F7)
    const after = snap(F7, { 'FIN-TSK-267': { title: 'W3-B Fix payee pattern for a card refund' } })
    // Same plan, same task set: no task-added. Its move into W3 reorders nothing that was already there. The set has no event
    // for a row changing wave; the page redraws from the snapshot, and W4 may add one if the motion needs it.
    expect(diff([before], [after])).toEqual([])
    expect(after.waves.find((w) => w.key === 'W3')?.members).toEqual(['FIN-TSK-266', 'FIN-TSK-267'])
  })
})
