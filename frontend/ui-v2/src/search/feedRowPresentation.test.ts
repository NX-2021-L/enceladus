import { describe, expect, it } from 'vitest'
import { feedRowAccent, priorityBadgeColor, sessionStateBadge } from './feedRowPresentation'

describe('feedRowAccent', () => {
  it('escalates P0 to the alert accent regardless of status', () => {
    expect(feedRowAccent({ status: 'open', priority: 'P0' })).toBe('var(--enc-crimson)')
  })
  it('renders blocked as alert', () => {
    expect(feedRowAccent({ status: 'blocked', priority: 'P2' })).toBe('var(--enc-crimson)')
  })
  it('renders in-progress as active (teal-light)', () => {
    expect(feedRowAccent({ status: 'in-progress', priority: 'P1' })).toBe('var(--enc-teal-light)')
  })
  it('renders closed as slate', () => {
    expect(feedRowAccent({ status: 'closed', priority: 'P2' })).toBe('var(--enc-slate)')
  })
  it('defaults open/neutral to teal', () => {
    expect(feedRowAccent({ status: 'open', priority: 'P2' })).toBe('var(--enc-teal)')
  })
})

describe('priorityBadgeColor', () => {
  it('maps P0 -> crimson, P1 -> amber, else dust', () => {
    expect(priorityBadgeColor('P0')).toBe('crimson')
    expect(priorityBadgeColor('P1')).toBe('amber')
    expect(priorityBadgeColor('P2')).toBe('dust')
    expect(priorityBadgeColor('P3')).toBe('dust')
  })
})

describe('sessionStateBadge', () => {
  it('returns null when there is no checkout signal (never fabricates one)', () => {
    expect(sessionStateBadge(undefined)).toBeNull()
  })
  it('maps checked_out -> amber CHECKED OUT', () => {
    expect(sessionStateBadge('checked_out')).toEqual({ label: 'CHECKED OUT', color: 'amber' })
  })
  it('maps any other present state -> teal CHECKED IN', () => {
    expect(sessionStateBadge('released')).toEqual({ label: 'CHECKED IN', color: 'teal' })
  })
})
