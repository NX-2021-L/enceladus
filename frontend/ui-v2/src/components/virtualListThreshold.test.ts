import { describe, expect, it } from 'vitest'
import { shouldVirtualize, VIRTUALIZE_ROW_THRESHOLD } from './virtualListThreshold'

describe('shouldVirtualize', () => {
  it('does not virtualize at or below the threshold', () => {
    expect(shouldVirtualize(0)).toBe(false)
    expect(shouldVirtualize(1)).toBe(false)
    expect(shouldVirtualize(VIRTUALIZE_ROW_THRESHOLD)).toBe(false)
  })

  it('virtualizes once a list exceeds the threshold (AC-3: >30 rows)', () => {
    expect(shouldVirtualize(VIRTUALIZE_ROW_THRESHOLD + 1)).toBe(true)
    expect(shouldVirtualize(200)).toBe(true)
  })

  it('threshold is exactly 30 per UX-A4 AC-3', () => {
    expect(VIRTUALIZE_ROW_THRESHOLD).toBe(30)
  })
})
