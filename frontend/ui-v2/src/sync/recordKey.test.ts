import { describe, expect, it } from 'vitest'
import {
  cacheKey,
  compareVersionTokens,
  isStrictlyNewerVersion,
  shouldAcceptRecord,
  shouldAcceptVersion,
  versionSeqFromUpdatedAt,
} from './recordKey'
import { maxVersionSeqBySource } from './feedVersionMeta'

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

describe('domain-safe version comparison (ENC-TSK-Q34 / ENC-ISS-731)', () => {
  it('compares integer seqs numerically, not lexically', () => {
    expect(compareVersionTokens('5101', '850')).toBe(1)
    expect(shouldAcceptVersion('850', '5101')).toBe(true)
    expect(shouldAcceptVersion('5101', '850')).toBe(false)
  })

  it('compares ISO tokens as times', () => {
    expect(compareVersionTokens('2026-10-08T02:29:33Z', '2026-10-01T19:13:52Z')).toBe(1)
    expect(shouldAcceptVersion('2026-10-08T02:29:33Z', '2026-10-01T19:13:52Z')).toBe(false)
  })

  it('never string-compares an ISO token against an integer seq', () => {
    expect(compareVersionTokens('2026-10-08T02:29:33Z', '8412')).toBeNull()
    // Pre-Q34 this was '2026-…' >= '8412' -> false, freezing the cached row.
    expect(shouldAcceptVersion('8412', '2026-10-08T02:29:33Z')).toBe(true)
  })

  it('never lets an empty "0" token displace a known version', () => {
    expect(shouldAcceptVersion('2026-10-08T02:29:33Z', '0')).toBe(false)
    expect(shouldAcceptVersion('0', '0')).toBe(true)
  })

  it('falls back to updated_at for a mixed record pair', () => {
    const cached = { versionSeq: '8412', updatedAt: '2026-10-01T00:00:00Z' }
    expect(shouldAcceptRecord(cached, { versionSeq: '2026-10-08T00:00:00Z', updatedAt: '2026-10-08T00:00:00Z' })).toBe(true)
    expect(shouldAcceptRecord(cached, { versionSeq: '2026-09-01T00:00:00Z', updatedAt: '2026-09-01T00:00:00Z' })).toBe(false)
  })

  it('compares a document seq only against document seqs', () => {
    // Document seqs (~185) and tracker seqs (~5100) are separate counters; a
    // given record only ever carries one, and the cursors never mix.
    expect(shouldAcceptRecord({ versionSeq: '185' }, { versionSeq: '186' })).toBe(true)
    expect(shouldAcceptRecord({ versionSeq: '186' }, { versionSeq: '185' })).toBe(false)
    expect(
      maxVersionSeqBySource([
        { source: 'tracker', version_seq: 5101 },
        { source: 'document', version_seq: 185 },
        { source: 'tracker', version_seq: 5099 },
      ]),
    ).toEqual({ tracker: 5101, document: 185 })
  })

  it('lifts a tombstone only for a strictly newer same-domain version', () => {
    expect(isStrictlyNewerVersion('190', '186')).toBe(true)
    expect(isStrictlyNewerVersion('186', '186')).toBe(false)
    expect(isStrictlyNewerVersion('2026-10-08T00:00:00Z', '186')).toBe(false)
  })
})
