import { describe, expect, it } from 'vitest'
import { excludeRecordType, onlyRecordType } from './recordTypeScope'
import type { LocalSearchRecord } from '../types/search'

const rows: LocalSearchRecord[] = [
  { recordId: 'ENC-TSK-1', recordType: 'task', projectId: 'enceladus', title: 'Task one' },
  { recordId: 'DOC-AAAA', recordType: 'document', projectId: 'global', title: 'Doc one' },
  { recordId: 'ENC-ISS-2', recordType: 'issue', projectId: 'enceladus', title: 'Issue one' },
  { recordId: 'DOC-BBBB', recordType: 'document', projectId: 'global', title: 'Doc two' },
]

describe('excludeRecordType', () => {
  it('drops rows matching the excluded type', () => {
    const result = excludeRecordType(rows, 'document')
    expect(result).toHaveLength(2)
    expect(result.every((r) => r.recordType !== 'document')).toBe(true)
  })

  it('is a no-op when the excluded type is absent', () => {
    const result = excludeRecordType(rows, 'plan')
    expect(result).toHaveLength(rows.length)
  })
})

describe('onlyRecordType', () => {
  it('keeps only rows matching the requested type', () => {
    const result = onlyRecordType(rows, 'document')
    expect(result).toHaveLength(2)
    expect(result.every((r) => r.recordType === 'document')).toBe(true)
    expect(result.map((r) => r.recordId)).toEqual(['DOC-AAAA', 'DOC-BBBB'])
  })

  it('returns an empty array when nothing matches', () => {
    expect(onlyRecordType(rows, 'lesson')).toEqual([])
  })
})

describe('reciprocal scoping invariant (ENC-TSK-L32 AC)', () => {
  it('feed scope (excludeRecordType document) and docs scope (onlyRecordType document) partition the corpus with no overlap', () => {
    const feedScope = excludeRecordType(rows, 'document')
    const docsScope = onlyRecordType(rows, 'document')
    expect(feedScope.length + docsScope.length).toBe(rows.length)
    const feedIds = new Set(feedScope.map((r) => r.recordId))
    const docsIds = new Set(docsScope.map((r) => r.recordId))
    for (const id of docsIds) expect(feedIds.has(id)).toBe(false)
  })
})
