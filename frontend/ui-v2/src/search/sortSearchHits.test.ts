import { describe, expect, it } from 'vitest'
import { sortSearchHits } from './sortSearchHits'
import type { SearchResultHit } from '../types/search'

const hits: SearchResultHit[] = [
  {
    recordId: 'ENC-TSK-BBB',
    recordType: 'task',
    projectId: 'enceladus',
    title: 'Bravo',
    status: 'open',
    tier: 'local',
  },
  {
    recordId: 'ENC-TSK-AAA',
    recordType: 'task',
    projectId: 'enceladus',
    title: 'Alpha',
    status: 'closed',
    tier: 'hybrid',
  },
]

describe('sortSearchHits', () => {
  it('preserves tier order by default', () => {
    expect(sortSearchHits(hits, 'tier').map((h) => h.recordId)).toEqual([
      'ENC-TSK-BBB',
      'ENC-TSK-AAA',
    ])
  })

  it('sorts by record id', () => {
    expect(sortSearchHits(hits, 'id').map((h) => h.recordId)).toEqual([
      'ENC-TSK-AAA',
      'ENC-TSK-BBB',
    ])
  })

  it('sorts by title', () => {
    expect(sortSearchHits(hits, 'title').map((h) => h.title)).toEqual(['Alpha', 'Bravo'])
  })

  it('sorts by last updated newest-first, with missing timestamps last (ENC-TSK-N56)', () => {
    const dated: SearchResultHit[] = [
      { recordId: 'ENC-TSK-1', recordType: 'task', projectId: 'enceladus', title: 'One', updatedAt: '2026-07-10T00:00:00Z' },
      { recordId: 'ENC-TSK-2', recordType: 'task', projectId: 'enceladus', title: 'Two', updatedAt: '2026-07-12T00:00:00Z' },
      { recordId: 'ENC-TSK-3', recordType: 'task', projectId: 'enceladus', title: 'Three' },
      { recordId: 'ENC-TSK-4', recordType: 'task', projectId: 'enceladus', title: 'Four', updatedAt: '2026-07-11T00:00:00Z' },
    ]
    expect(sortSearchHits(dated, 'updated').map((h) => h.recordId)).toEqual([
      'ENC-TSK-2',
      'ENC-TSK-4',
      'ENC-TSK-1',
      'ENC-TSK-3',
    ])
  })
})
