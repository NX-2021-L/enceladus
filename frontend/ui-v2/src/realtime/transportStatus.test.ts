import { describe, expect, it } from 'vitest'
import { feedTransportLabel } from './transportStatus'
import type { RealtimeConnectionPhase } from '../types/feedEvents'

/**
 * ENC-TSK-M82 (AC-3): the header label must reflect ACTUAL transport state.
 * `LIVE` is reserved for a real open WSS (phase 'connected' == connection_ack
 * received); every fallback/degraded phase must read honestly as SNAPSHOT.
 */
describe('feedTransportLabel — truthful header transport label (ENC-TSK-M82)', () => {
  it("says LIVE only when the socket is connected (connection_ack received)", () => {
    expect(feedTransportLabel('connected')).toBe('LIVE')
  })

  it('says SNAPSHOT for every non-connected phase (S3 snapshot / delta-poll fallback)', () => {
    const fallbackPhases: RealtimeConnectionPhase[] = [
      'idle',
      'connecting',
      'reconnecting',
      'disconnected',
      'manual_retry',
    ]
    for (const phase of fallbackPhases) {
      expect(feedTransportLabel(phase)).toBe('SNAPSHOT')
    }
  })

  it('never claims LIVE while merely connecting — the exact masking defect io caught', () => {
    // Before this task the eyebrow was a hardcoded `FEED · LIVE`, so a total
    // transport failure (zero sockets) still rendered LIVE. A connecting/idle
    // phase must NOT read LIVE.
    expect(feedTransportLabel('connecting')).not.toBe('LIVE')
    expect(feedTransportLabel('idle')).not.toBe('LIVE')
  })
})
