import { beforeEach, describe, expect, it } from 'vitest'
import { getRecentlyViewed, trackRecentlyViewed } from './recentlyViewed'
import type { SearchResultHit } from '../types/search'

const HIT = (id: string, type: SearchResultHit['recordType'] = 'task'): SearchResultHit => ({
  recordId: id,
  recordType: type,
  projectId: 'enceladus',
  title: `Title ${id}`,
  tier: 'local',
})

describe('recentlyViewed', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('stores entries per record type', () => {
    trackRecentlyViewed(HIT('ENC-TSK-001', 'task'))
    trackRecentlyViewed(HIT('ENC-ISS-001', 'issue'))
    expect(getRecentlyViewed('task')).toHaveLength(1)
    expect(getRecentlyViewed('issue')).toHaveLength(1)
  })

  it('orders by last-viewed desc and dedupes', () => {
    trackRecentlyViewed(HIT('ENC-TSK-A'))
    trackRecentlyViewed(HIT('ENC-TSK-B'))
    trackRecentlyViewed(HIT('ENC-TSK-A'))
    const list = getRecentlyViewed('task')
    expect(list[0]?.recordId).toBe('ENC-TSK-A')
    expect(list).toHaveLength(2)
  })
})
