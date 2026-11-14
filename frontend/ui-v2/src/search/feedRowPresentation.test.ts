import { describe, expect, it } from 'vitest'
import { priorityBadgeColor, sessionStateBadge } from './feedRowPresentation'

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
