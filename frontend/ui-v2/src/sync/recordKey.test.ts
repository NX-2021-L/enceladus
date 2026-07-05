import { describe, expect, it } from 'vitest'
import { cacheKey, shouldAcceptVersion, versionSeqFromUpdatedAt } from './recordKey'

describe('recordKey helpers', () => {
  it('builds stable cache keys', () => {
    expect(cacheKey('enceladus', 'ENC-TSK-1')).toBe('enceladus:ENC-TSK-1')
    expect(cacheKey('', 'DOC-1')).toBe('global:DOC-1')
  })

  it('derives version seq from updated_at', () => {
    expect(versionSeqFromUpdatedAt('2026-07-05T00:00:00Z')).toBe('2026-07-05T00:00:00Z')
    expect(versionSeqFromUpdatedAt(null)).toBe('0')
  })

  it('accepts newer or equal version sequences', () => {
    expect(shouldAcceptVersion(undefined, '2')).toBe(true)
    expect(shouldAcceptVersion('2', '2')).toBe(true)
    expect(shouldAcceptVersion('2', '3')).toBe(true)
    expect(shouldAcceptVersion('3', '2')).toBe(false)
  })
})
