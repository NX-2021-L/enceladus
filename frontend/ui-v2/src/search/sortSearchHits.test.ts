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
})
