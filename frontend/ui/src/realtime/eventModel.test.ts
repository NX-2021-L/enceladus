import { describe, it, expect } from 'vitest'
import { parseFeedEvent, isGapTooLarge } from './eventModel'

const validEvent = {
  eventId: '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b',
  recordId: 'ENC-TSK-B67',
  record_type: 'task',
  action: 'status_changed',
  actorType: 'agent',
  actorId: 'ENC-SES-003',
  summary: 'agent ENC-SES-003 moved task ENC-TSK-B67 from open to in-progress',
  cursor: 1782640000000,
  context_node: {
    freshness_score: 0.99,
    structural_importance: 0.2,
    information_density: 0.5,
    access_frequency: 0,
  },
}

describe('parseFeedEvent (AC-10 contract)', () => {
  it('accepts a valid event object', () => {
    const e = parseFeedEvent(validEvent)
    expect(e).not.toBeNull()
    expect(e?.recordId).toBe('ENC-TSK-B67')
    expect(e?.actorType).toBe('agent')
  })

  it('parses a JSON string payload (client only JSON.parse + validate)', () => {
    const e = parseFeedEvent(JSON.stringify(validEvent))
    expect(e?.cursor).toBe(1782640000000)
  })

  it('rejects a non-UUIDv7 eventId', () => {
    expect(parseFeedEvent({ ...validEvent, eventId: 'not-a-uuid' })).toBeNull()
  })

  it('rejects a v4 uuid (must be timestamp-sortable v7)', () => {
    expect(
      parseFeedEvent({ ...validEvent, eventId: '0190a1b2-c3d4-4e5f-8a9b-0c1d2e3f4a5b' }),
    ).toBeNull()
  })

  it('rejects an invalid actorType', () => {
    expect(parseFeedEvent({ ...validEvent, actorType: 'robot' })).toBeNull()
  })

  it('rejects a missing summary', () => {
    const rest: Record<string, unknown> = { ...validEvent }
    delete rest.summary
    expect(parseFeedEvent(rest)).toBeNull()
  })

  it('rejects a non-numeric cursor', () => {
    expect(parseFeedEvent({ ...validEvent, cursor: 'abc' })).toBeNull()
  })

  it('drops malformed JSON strings', () => {
    expect(parseFeedEvent('{not json')).toBeNull()
  })

  it('omits context_node when malformed but keeps the event', () => {
    const e = parseFeedEvent({ ...validEvent, context_node: { freshness_score: 'x' } })
    expect(e).not.toBeNull()
    expect(e?.context_node).toBeUndefined()
  })
})

describe('isGapTooLarge', () => {
  it('detects the gap signal', () => {
    expect(isGapTooLarge({ type: 'gap_too_large', lastReceivedCursor: 5 })).toBe(true)
  })
  it('ignores normal events', () => {
    expect(isGapTooLarge(validEvent)).toBe(false)
  })
})
