import { describe, expect, it } from 'vitest'
import { applyPropertyFilter } from './applyPropertyFilter'
import type { SearchResultHit } from '../types/search'

const HITS: SearchResultHit[] = [
  {
    recordId: 'ENC-TSK-L19',
    recordType: 'task',
    projectId: 'enceladus',
    title: 'Feed search',
    status: 'in-progress',
    tier: 'local',
  },
  {
    recordId: 'ENC-ISS-058',
    recordType: 'issue',
    projectId: 'enceladus',
    title: 'Issue',
    status: 'open',
    tier: 'hybrid',
  },
]

describe('applyPropertyFilter', () => {
  it('returns all hits when no tokens', () => {
    expect(applyPropertyFilter(HITS, { tokens: [] })).toHaveLength(2)
  })

  it('filters by status token pill', () => {
    const filtered = applyPropertyFilter(HITS, {
      tokens: [{ propertyKey: 'status', operator: '=', value: 'open' }],
    })
    expect(filtered).toHaveLength(1)
    expect(filtered[0]?.recordId).toBe('ENC-ISS-058')
  })

  it('filters by record_type token', () => {
    const filtered = applyPropertyFilter(HITS, {
      tokens: [{ propertyKey: 'record_type', operator: '=', value: 'task' }],
    })
    expect(filtered).toHaveLength(1)
    expect(filtered[0]?.recordType).toBe('task')
  })
})
