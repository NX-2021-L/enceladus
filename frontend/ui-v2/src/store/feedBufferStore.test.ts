import { beforeEach, describe, expect, it } from 'vitest'
import { useFeedBufferStore } from './feedBufferStore'
import type { FeedRealtimeEvent } from '../types/feedEvents'

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

describe('feedBufferStore (ENC-TSK-K24 / B67 AC-11)', () => {
  beforeEach(() => {
    useFeedBufferStore.getState().clear()
  })

  it('accumulates buffered events without merging them into anything visible', () => {
    useFeedBufferStore.getState().bufferEvent(event({ eventId: 'a', cursor: 1 }))
    useFeedBufferStore.getState().bufferEvent(event({ eventId: 'b', cursor: 2 }))
    expect(useFeedBufferStore.getState().bufferedEvents).toHaveLength(2)
  })

  it('de-dupes by eventId within the buffer (reconnect replay redelivering an already-buffered event)', () => {
    useFeedBufferStore.getState().bufferEvent(event({ eventId: 'a', cursor: 1, summary: 'first' }))
    useFeedBufferStore.getState().bufferEvent(event({ eventId: 'a', cursor: 1, summary: 'first' }))
    expect(useFeedBufferStore.getState().bufferedEvents).toHaveLength(1)
  })

  it('drainBuffer returns the events and clears the buffer atomically', () => {
    useFeedBufferStore.getState().bufferEvent(event({ eventId: 'a', cursor: 1 }))
    useFeedBufferStore.getState().bufferEvent(event({ eventId: 'b', cursor: 2 }))

    const drained = useFeedBufferStore.getState().drainBuffer()
    expect(drained).toHaveLength(2)
    expect(useFeedBufferStore.getState().bufferedEvents).toHaveLength(0)
  })

  it('drainBuffer on an empty buffer returns an empty array, not undefined', () => {
    expect(useFeedBufferStore.getState().drainBuffer()).toEqual([])
  })
})
