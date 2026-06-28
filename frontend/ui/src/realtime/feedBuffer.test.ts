import { describe, it, expect, beforeEach } from 'vitest'
import { useFeedBuffer } from './feedBuffer'
import type { FeedEvent } from './eventModel'

function makeEvent(overrides: Partial<FeedEvent> = {}): FeedEvent {
  return {
    eventId: overrides.eventId ?? `0190a1b2-c3d4-7e5f-8a9b-${Math.random().toString(16).slice(2, 14).padEnd(12, '0')}`,
    recordId: overrides.recordId ?? 'ENC-TSK-B67',
    record_type: 'task',
    action: 'updated',
    actorType: 'agent',
    actorId: 'ENC-SES-003',
    summary: 'summary',
    cursor: overrides.cursor ?? 1,
    ...overrides,
  }
}

describe('feedBuffer dedup + banner (AC-9, AC-11)', () => {
  beforeEach(() => useFeedBuffer.getState().reset())

  it('buffers incoming events without auto-injecting (banner count)', () => {
    const s = useFeedBuffer.getState()
    s.ingest(makeEvent({ eventId: 'a', cursor: 1 }))
    s.ingest(makeEvent({ eventId: 'b', cursor: 2 }))
    expect(useFeedBuffer.getState().bannerCount()).toBe(2)
  })

  it('drains buffer on banner click and clears it', () => {
    const s = useFeedBuffer.getState()
    s.ingest(makeEvent({ eventId: 'a', cursor: 1 }))
    const drained = useFeedBuffer.getState().drain()
    expect(drained).toHaveLength(1)
    expect(useFeedBuffer.getState().bannerCount()).toBe(0)
  })

  it('Layer 1: replaces optimistic event by eventId instead of duplicating', () => {
    const s = useFeedBuffer.getState()
    s.registerOptimistic('evt-1')
    // optimistic placeholder is in the buffer already (simulate prepend)
    useFeedBuffer.setState((st) => ({
      buffer: [makeEvent({ eventId: 'evt-1', cursor: 1, pending: true }), ...st.buffer],
    }))
    s.ingest(makeEvent({ eventId: 'evt-1', cursor: 1 }))
    const buf = useFeedBuffer.getState().buffer
    expect(buf).toHaveLength(1)
    expect(buf[0].pending).toBe(false)
  })

  it('drops duplicate eventIds under replay (idempotent)', () => {
    const s = useFeedBuffer.getState()
    s.ingest(makeEvent({ eventId: 'dup', cursor: 1 }))
    s.ingest(makeEvent({ eventId: 'dup', cursor: 1 }))
    expect(useFeedBuffer.getState().bannerCount()).toBe(1)
  })

  it('tracks the highest received cursor for gap recovery', () => {
    const s = useFeedBuffer.getState()
    s.ingest(makeEvent({ eventId: 'a', cursor: 10 }))
    s.ingest(makeEvent({ eventId: 'b', cursor: 5 }))
    expect(useFeedBuffer.getState().lastReceivedCursor).toBe(10)
  })
})
