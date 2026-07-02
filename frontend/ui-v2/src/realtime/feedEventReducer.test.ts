import { describe, expect, it } from 'vitest'
import {
  filterFeedEvents,
  mergeFeedEvents,
  maxCursor,
} from './feedEventReducer'
import type { FeedRealtimeEvent } from '../../types/feedEvents'

function event(partial: Partial<FeedRealtimeEvent> & Pick<FeedRealtimeEvent, 'eventId' | 'cursor'>): FeedRealtimeEvent {
  return {
    recordId: 'ENC-TSK-001',
    record_type: 'task',
    action: 'updated',
    actorType: 'agent',
    actorId: 'ENC-SES-001',
    summary: 'test',
    channels: ['/feed/updates'],
    ...partial,
  }
}

describe('feedEventReducer', () => {
  it('merges by eventId and sorts by cursor desc', () => {
    const a = event({ eventId: 'a', cursor: 100 })
    const b = event({ eventId: 'b', cursor: 200 })
    const merged = mergeFeedEvents([a], [b, { ...a, summary: 'updated' }])
    expect(merged).toHaveLength(2)
    expect(merged[0]?.eventId).toBe('b')
    expect(merged.find((e) => e.eventId === 'a')?.summary).toBe('updated')
  })

  it('filters by record type when filters are active', () => {
    const tasks = event({ eventId: 't1', cursor: 1, record_type: 'task' })
    const issues = event({ eventId: 'i1', cursor: 2, record_type: 'issue' })
    const filtered = filterFeedEvents([tasks, issues], ['task'])
    expect(filtered).toHaveLength(1)
    expect(filtered[0]?.record_type).toBe('task')
  })

  it('computes max cursor', () => {
    expect(maxCursor([event({ eventId: 'a', cursor: 10 }), event({ eventId: 'b', cursor: 99 })])).toBe(99)
  })
})
