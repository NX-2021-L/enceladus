import { describe, expect, it } from 'vitest'
import { formatRelativeTime } from './relativeTime'

describe('formatRelativeTime', () => {
  const now = Date.parse('2026-07-08T12:00:00Z')

  it('returns null for missing input', () => {
    expect(formatRelativeTime(undefined, now)).toBeNull()
    expect(formatRelativeTime(null, now)).toBeNull()
  })

  it('returns null for unparseable input rather than fabricating a time', () => {
    expect(formatRelativeTime('not-a-date', now)).toBeNull()
  })

  it('formats minutes', () => {
    expect(formatRelativeTime('2026-07-08T11:37:00Z', now)).toBe('23m ago')
  })

  it('formats hours', () => {
    expect(formatRelativeTime('2026-07-08T09:00:00Z', now)).toBe('3h ago')
  })

  it('formats days', () => {
    expect(formatRelativeTime('2026-07-05T12:00:00Z', now)).toBe('3d ago')
  })

  it('formats sub-minute as "just now"', () => {
    expect(formatRelativeTime('2026-07-08T11:59:50Z', now)).toBe('just now')
  })
})
