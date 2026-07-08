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
  {
    recordId: 'ENC-TSK-M40',
    recordType: 'task',
    projectId: 'enceladus',
    title: 'Open P0 task',
    status: 'open',
    priority: 'P0',
    checkoutState: 'checked_out',
    tier: 'local',
  },
  {
    recordId: 'ENC-TSK-M41',
    recordType: 'task',
    projectId: 'enceladus',
    title: 'Open P2 task',
    status: 'open',
    priority: 'P2',
    checkoutState: 'available',
    tier: 'local',
  },
]

describe('applyPropertyFilter', () => {
  it('returns all hits when no tokens', () => {
    expect(applyPropertyFilter(HITS, { tokens: [] })).toHaveLength(HITS.length)
  })

  it('filters by status token pill', () => {
    const filtered = applyPropertyFilter(HITS, {
      tokens: [{ propertyKey: 'status', operator: '=', value: 'open' }],
    })
    expect(filtered.map((h) => h.recordId).sort()).toEqual(
      ['ENC-ISS-058', 'ENC-TSK-M40', 'ENC-TSK-M41'].sort(),
    )
  })

  it('filters by record_type token', () => {
    const filtered = applyPropertyFilter(HITS, {
      tokens: [{ propertyKey: 'record_type', operator: '=', value: 'task' }],
    })
    expect(filtered).toHaveLength(3)
    expect(filtered.every((h) => h.recordType === 'task')).toBe(true)
  })

  it('"in" operator matches any comma-separated value (Home "Open P0/P1" deep link)', () => {
    const filtered = applyPropertyFilter(HITS, {
      tokens: [
        { propertyKey: 'status', operator: '=', value: 'open' },
        { propertyKey: 'priority', operator: 'in', value: 'p0,p1' },
      ],
    })
    expect(filtered).toHaveLength(1)
    expect(filtered[0]?.recordId).toBe('ENC-TSK-M40')
  })

  it('filters by checkout_state != (Home "Awaiting checkout" deep link)', () => {
    const filtered = applyPropertyFilter(HITS, {
      tokens: [
        { propertyKey: 'record_type', operator: '=', value: 'task' },
        { propertyKey: 'status', operator: '=', value: 'open' },
        { propertyKey: 'checkout_state', operator: '!=', value: 'checked_out' },
      ],
    })
    expect(filtered).toHaveLength(1)
    expect(filtered[0]?.recordId).toBe('ENC-TSK-M41')
  })
})
