import { describe, expect, it } from 'vitest'
import { expandedDefault, isHot, isTerminal, makeOverride, shown, waveState, waveStatus, type WaveFacts, type WaveTaskFacts } from './waveState'

const CO = '2026-11-14T00:58:09Z'
const open = (extra: Partial<WaveTaskFacts> = {}): WaveTaskFacts => ({ status: 'open', ...extra })
const inProgress = (extra: Partial<WaveTaskFacts> = {}): WaveTaskFacts => ({ status: 'in-progress', first_checked_out_at: CO, ...extra })
const closed = (extra: Partial<WaveTaskFacts> = {}): WaveTaskFacts => ({ status: 'closed', first_checked_out_at: CO, ...extra })
const wave = (members: WaveTaskFacts[], parent?: WaveTaskFacts | null): WaveFacts => ({ members, parent })

describe('terminal and open', () => {
  it('closed and superseded are terminal; everything else is open', () => {
    expect(isTerminal({ status: 'closed' })).toBe(true)
    expect(isTerminal({ status: 'superseded' })).toBe(true)
    expect(isTerminal({ status: 'Closed ' })).toBe(true)
    for (const s of ['open', 'in-progress', 'pr', 'deployed', 'coding-updates', null, undefined]) expect(isTerminal({ status: s })).toBe(false)
  })
})

describe('touched, hot, resolved', () => {
  it('touched(w): some member has first_checked_out_at', () => {
    expect(waveStatus(wave([open(), open({ first_checked_out_at: CO })])).touched).toBe(true)
    expect(waveStatus(wave([open(), open()])).touched).toBe(false)
    expect(waveStatus(wave([])).touched).toBe(false)
  })

  it('touched(w) falls back to checkout_state = checked_out or an in-flight status before the backfill', () => {
    expect(waveStatus(wave([open({ checkout_state: 'checked_out' })])).touched).toBe(true)
    expect(waveStatus(wave([open({ checkout_state: 'checked-out' })])).touched).toBe(true)
    expect(waveStatus(wave([open({ checkout_state: 'checked_in' })])).touched).toBe(false)
    for (const status of ['in-progress', 'in_progress', 'coding-complete', 'committed', 'pr', 'merged-main', 'merged_main', 'deploy-init', 'deploy-success', 'deployed', 'coding-updates']) {
      expect(waveStatus(wave([{ status }])).touched, status).toBe(true)
    }
    for (const status of ['open', 'closed', 'superseded', 'nonsense', null]) expect(waveStatus(wave([{ status }])).touched, String(status)).toBe(false)
  })

  it('hot(w): some member has first_checked_out_at and is open', () => {
    expect(isHot(wave([inProgress()]))).toBe(true)
    expect(isHot(wave([closed(), open()]))).toBe(false)
    expect(isHot(wave([closed(), inProgress()]))).toBe(true)
    expect(isHot(wave([closed()]))).toBe(false)
    expect(isHot(wave([]))).toBe(false)
  })

  it('hot(w) reads first_checked_out_at alone: the pre-backfill fallback is for touched(w) only (section 5.5)', () => {
    const w = wave([{ status: 'in-progress', checkout_state: 'checked_out' }])
    expect(waveStatus(w).touched).toBe(true)
    expect(waveStatus(w).hot).toBe(false)
  })

  it('resolved(w) with no parent: members non-empty and every member terminal', () => {
    expect(waveStatus(wave([closed(), closed()])).resolved).toBe(true)
    expect(waveStatus(wave([closed(), { status: 'superseded' }])).resolved).toBe(true)
    expect(waveStatus(wave([closed(), open()])).resolved).toBe(false)
    expect(waveStatus(wave([])).resolved).toBe(false)
  })

  it('resolved(w) with a parent: the parent is closed, whatever the members say', () => {
    expect(waveStatus(wave([open()], { status: 'closed' })).resolved).toBe(true)
    expect(waveStatus(wave([closed()], { status: 'in-progress' })).resolved).toBe(false)
    expect(waveStatus(wave([closed()], { status: 'superseded' })).resolved).toBe(false)
    expect(waveStatus(wave([], { status: 'closed' })).resolved).toBe(true)
  })
})

describe('waveState', () => {
  it('todo: nothing has been checked out', () => {
    expect(waveState(wave([open(), open()]))).toBe('todo')
    expect(waveState(wave([open()], { status: 'open' }))).toBe('todo')
    expect(waveState(wave([]))).toBe('todo')
  })

  it('active: touched and not resolved (R9)', () => {
    expect(waveState(wave([inProgress(), open()], { status: 'in-progress' }))).toBe('active')
    expect(waveState(wave([closed(), open()]))).toBe('active')
  })

  it('done: resolved (R10)', () => {
    expect(waveState(wave([closed(), closed()]))).toBe('done')
    expect(waveState(wave([open()], { status: 'closed' }))).toBe('done')
  })

  it('done beats touched', () => {
    expect(waveStatus(wave([closed()], { status: 'closed' }))).toMatchObject({ touched: true, resolved: true, state: 'done' })
  })
})

describe('settling (decision D-2)', () => {
  // ENC-PLN-106 W2: ENC-TSK-S61-0A closed at 2026-11-14T03:57Z, its wave parent ENC-TSK-S61 closed at 04:12Z.
  const members = [closed({ first_checked_out_at: '2026-11-14T00:58:09Z' })]

  it('every member closed while the parent is still open keeps the in-progress color and is not hot', () => {
    expect(waveStatus(wave(members, { status: 'in-progress' }))).toEqual({ touched: true, hot: false, resolved: false, settling: true, state: 'active' })
  })

  it('is collapsed by default on a started plan, because nothing in it is hot', () => {
    expect(expandedDefault(wave(members, { status: 'in-progress' }), 'started')).toBe(false)
  })

  it('ends when the parent closes: the wave is then done, and no longer settling', () => {
    expect(waveStatus(wave(members, { status: 'closed' }))).toMatchObject({ settling: false, state: 'done' })
  })

  it('needs a parent: a parentless wave whose members are all closed is done, not settling', () => {
    expect(waveStatus(wave(members))).toMatchObject({ settling: false, state: 'done' })
  })

  it('needs members: a parent alone is not settling', () => {
    expect(waveStatus(wave([], { status: 'in-progress' })).settling).toBe(false)
  })
})

describe('regression is legal (invariant 7): state is recomputed, never remembered', () => {
  it('a task that re-enters after close returns a parentless wave from done to active, and hot', () => {
    const before = wave([closed(), closed()])
    expect(waveState(before)).toBe('done')
    const after = wave([closed(), { ...closed(), status: 'in-progress' }])
    expect(waveStatus(after)).toMatchObject({ state: 'active', hot: true, resolved: false })
    expect(expandedDefault(after, 'started')).toBe(true)
  })

  it('reopening the wave parent returns a wave from done to active (settling), and a reopened member makes it hot', () => {
    const members = [closed(), closed()]
    expect(waveState(wave(members, { status: 'closed' }))).toBe('done')
    expect(waveStatus(wave(members, { status: 'in-progress' }))).toMatchObject({ state: 'active', settling: true, hot: false })
    expect(waveStatus(wave([closed(), { ...closed(), status: 'in-progress' }], { status: 'in-progress' }))).toMatchObject({ state: 'active', hot: true })
  })

  it('under a parent that is still closed, a member that re-enters does not change the state: the parent decides', () => {
    expect(waveState(wave([closed(), { ...closed(), status: 'in-progress' }], { status: 'closed' }))).toBe('done')
  })

  it('a closed task that never had a checkout stamp and re-enters is still touched through its status', () => {
    expect(waveState(wave([{ status: 'in-progress' }]))).toBe('active')
  })
})

describe('expandedDefault', () => {
  const hotWave = wave([inProgress()], { status: 'in-progress' })

  it('R8: a hot wave expands on a started plan, and on an incomplete one', () => {
    expect(expandedDefault(hotWave, 'started')).toBe(true)
    expect(expandedDefault(hotWave, 'incomplete')).toBe(true)
  })

  it('R7: every wave of a drafted plan is collapsed, hot or not; a complete plan likewise', () => {
    expect(expandedDefault(hotWave, 'drafted')).toBe(false)
    expect(expandedDefault(hotWave, 'complete')).toBe(false)
    expect(expandedDefault(hotWave, null)).toBe(false)
    expect(expandedDefault(hotWave, undefined)).toBe(false)
    expect(expandedDefault(hotWave, 'unknown')).toBe(false)
  })

  it('normalises the plan status', () => {
    expect(expandedDefault(hotWave, ' Started ')).toBe(true)
  })

  it('R10: a done wave is collapsed by default', () => {
    expect(expandedDefault(wave([closed()], { status: 'closed' }), 'started')).toBe(false)
  })

  it('a done wave is collapsed even if a member is still hot under a closed parent', () => {
    const w = wave([inProgress()], { status: 'closed' })
    expect(waveStatus(w)).toMatchObject({ hot: true, state: 'done' })
    expect(expandedDefault(w, 'started')).toBe(false)
  })

  it('a todo wave and an active wave with nothing hot are collapsed', () => {
    expect(expandedDefault(wave([open()]), 'started')).toBe(false)
    expect(expandedDefault(wave([closed(), open()]), 'started')).toBe(false)
  })
})

describe('shown: a manual override lasts until state or hotness next changes (decision D-3)', () => {
  const quiet = wave([closed(), open()]) // active, not hot
  const nowHot = wave([closed(), inProgress()]) // active, hot
  const done = wave([closed(), closed()])

  it('falls back to expandedDefault with no override', () => {
    expect(shown(quiet, 'started')).toBe(false)
    expect(shown(nowHot, 'started')).toBe(true)
    expect(shown(nowHot, 'started', null)).toBe(true)
  })

  it('the override wins while neither state nor hotness has changed', () => {
    expect(shown(quiet, 'started', makeOverride(quiet, true))).toBe(true)
    expect(shown(nowHot, 'started', makeOverride(nowHot, false))).toBe(false)
  })

  it('a change of hotness clears the override, so the automatic expansion fires on the real transition', () => {
    const collapsedByUser = makeOverride(quiet, false)
    expect(shown(quiet, 'started', collapsedByUser)).toBe(false)
    expect(shown(nowHot, 'started', collapsedByUser)).toBe(true)
  })

  it('a change of state clears the override, so a finished wave collapses', () => {
    const openedByUser = makeOverride(nowHot, true)
    expect(shown(done, 'started', openedByUser)).toBe(false)
  })

  it('records the state and hotness it was made under', () => {
    expect(makeOverride(nowHot, true)).toEqual({ expanded: true, state: 'active', hot: true })
    expect(makeOverride(done, false)).toEqual({ expanded: false, state: 'done', hot: false })
  })
})

/**
 * ENC-TSK-T22 (ENC-ISS-922): criterion 8's missing conjunct, asserted on the lens rather than on the page.
 *
 * hot(w) is defined on co(t) ALONE -- section 5.5's pre-backfill fallback is stated for touched(w) only -- so a member
 * known to be checked out but carrying no first_checked_out_at makes a wave `active` and NOT hot, and expandedDefault
 * stays false. That is the whole of the defect: the stamp was reaching the client on the live event and being dropped
 * before the lens saw it.
 */
describe('a member checked out with no stamp is active but not hot (ENC-TSK-T22)', () => {
  const parent = { status: 'open' }

  it('is active and NOT hot, so a started plan does not expand it', () => {
    const w = { parent, members: [{ status: 'in-progress', checkout_state: 'checked_out' }] }
    const st = waveStatus(w)
    expect(st.touched).toBe(true)
    expect(st.state).toBe('active')
    expect(st.hot).toBe(false)
    expect(expandedDefault(w, 'started')).toBe(false)
  })

  it('becomes hot once the stamp arrives, and a started plan expands it', () => {
    const w = {
      parent,
      members: [{ status: 'in-progress', checkout_state: 'checked_out', first_checked_out_at: '2026-11-20T03:39:52Z' }],
    }
    const st = waveStatus(w)
    expect(st.state).toBe('active')
    expect(st.hot).toBe(true)
    expect(expandedDefault(w, 'started')).toBe(true)
    // R7 still holds: a drafted plan collapses everything however hot the wave is.
    expect(expandedDefault(w, 'drafted')).toBe(false)
  })

  it('a stamped member that is terminal is not hot, so a finished wave does not reopen', () => {
    const w = { parent, members: [{ status: 'closed', first_checked_out_at: '2026-11-20T03:39:52Z' }] }
    expect(waveStatus(w).hot).toBe(false)
    expect(expandedDefault(w, 'started')).toBe(false)
  })
})
