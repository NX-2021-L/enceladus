import { describe, expect, it } from 'vitest'
import { computePrimaryActions, isCheckedOut, arcFor } from './transitionArcs'

/**
 * ENC-TSK-M33 -- transition-computation logic tested against representative
 * records pulled from live governed data (DOC-B6B52E3BB9BB §4): a task in
 * 'pr' checked out by an agent session, an open issue, a planned feature,
 * and a closed issue. No live write/click coverage here (agent sessions
 * don't re-inject Cognito) -- this is the pure-logic contract the state-aware
 * action bar renders from.
 */

describe('isCheckedOut', () => {
  it('is true when active_agent_session is true', () => {
    expect(isCheckedOut({ active_agent_session: true })).toBe(true)
  })

  it('falls back to checkout_state when active_agent_session is absent', () => {
    expect(isCheckedOut({ checkout_state: 'checked_out' })).toBe(true)
  })

  it('is false for a checked-in record', () => {
    expect(isCheckedOut({ active_agent_session: false, checkout_state: 'checked_in' })).toBe(false)
  })
})

describe('computePrimaryActions -- representative records', () => {
  it('task ENC-TSK-M31 shape: status=pr, checked_out by an agent session -> Check In only', () => {
    const actions = computePrimaryActions({
      recordType: 'task',
      status: 'pr',
      transitionType: 'github_pr_deploy',
      checkedOut: true,
    })
    expect(actions).toEqual([{ kind: 'check-in', label: 'Check In' }])
  })

  it('open issue -> advance to in-progress, no revert (already at arc start)', () => {
    const actions = computePrimaryActions({
      recordType: 'issue',
      status: 'open',
      checkedOut: false,
    })
    expect(actions).toHaveLength(1)
    expect(actions[0]).toMatchObject({ kind: 'advance', targetStatus: 'in-progress', label: 'In Progress →' })
  })

  it('planned feature -> advance to in-progress, no revert (already at arc start)', () => {
    const actions = computePrimaryActions({
      recordType: 'feature',
      status: 'planned',
      checkedOut: false,
    })
    expect(actions).toHaveLength(1)
    expect(actions[0]).toMatchObject({ kind: 'advance', targetStatus: 'in-progress', label: 'In Progress →' })
  })

  it('closed issue -> revert to in-progress, no advance (terminal in its arc)', () => {
    const actions = computePrimaryActions({
      recordType: 'issue',
      status: 'closed',
      checkedOut: false,
    })
    expect(actions).toHaveLength(1)
    expect(actions[0]).toMatchObject({ kind: 'revert', targetStatus: 'in-progress', label: '← In Progress' })
  })

  it('task not checked out, mid-arc (committed) -> both revert and advance, advance allows Submit + Close', () => {
    const actions = computePrimaryActions({
      recordType: 'task',
      status: 'committed',
      transitionType: 'github_pr_deploy',
      checkedOut: false,
    })
    expect(actions).toHaveLength(2)
    expect(actions[0]).toMatchObject({ kind: 'revert', targetStatus: 'coding-complete' })
    expect(actions[1]).toMatchObject({ kind: 'advance', targetStatus: 'pr', allowSubmitClose: true })
  })

  it('task at final arc status (closed) -> no actions at all (terminal, not checked out)', () => {
    const actions = computePrimaryActions({
      recordType: 'task',
      status: 'closed',
      transitionType: 'github_pr_deploy',
      checkedOut: false,
    })
    expect(actions).toHaveLength(1)
    expect(actions[0].kind).toBe('revert')
    expect(actions[0].targetStatus).toBe('deploy-success')
  })

  it('code_only task at merged-main -> advance target is closed (shorter arc), no deploy-init/success stage', () => {
    const actions = computePrimaryActions({
      recordType: 'task',
      status: 'merged-main',
      transitionType: 'code_only',
      checkedOut: false,
    })
    const advance = actions.find((a) => a.kind === 'advance')
    expect(advance?.targetStatus).toBe('closed')
    // code_only tasks jump straight to closed here -- Submit + Close would be
    // a no-op duplicate of the plain advance, so it's suppressed.
    expect(advance?.allowSubmitClose).toBe(false)
  })

  it('no_code task arc is the shortest: open -> in-progress -> coding-complete -> closed', () => {
    expect(arcFor('task', 'no_code')).toEqual(['open', 'in-progress', 'coding-complete', 'closed'])
  })

  it('unknown status not present in the computed arc -> disabled advance with an honest reason, not a faked transition', () => {
    const actions = computePrimaryActions({
      recordType: 'task',
      status: 'some-unrecognized-status',
      transitionType: 'github_pr_deploy',
      checkedOut: false,
    })
    expect(actions).toHaveLength(1)
    expect(actions[0]).toMatchObject({ kind: 'advance', disabled: true })
    expect(actions[0].disabledReason).toMatch(/isn't recognized/)
  })

  it('unknown task transition_type falls back to the strictest arc (github_pr_deploy) rather than allowing nothing', () => {
    expect(arcFor('task', 'some_future_transition_type')).toEqual(arcFor('task', 'github_pr_deploy'))
  })

  it('plan arcs and feature arcs are exposed for completeness (no transition_type dependency)', () => {
    expect(arcFor('plan')).toEqual(['drafted', 'started', 'complete', 'incomplete'])
    expect(arcFor('feature')).toEqual(['planned', 'in-progress', 'completed', 'production', 'deprecated'])
  })
})
