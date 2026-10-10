import { describe, expect, it } from 'vitest'
import { DEFAULT_FEED_ENGINE, resolveFeedEngine } from './feedEngine'
import { BACKOFF_BASE_MS, BACKOFF_CAP_MS, DEFAULT_CONNECTION_TIMEOUT_MS, LIVENESS_CHECK_INTERVAL_MS, MAX_AUTO_RECONNECT_ATTEMPTS } from '../realtime/appsyncRealtimeClient'
import { backoffDelay } from '@io-kit/feed/appsync'

describe('feed engine flag (default legacy again since DVP-TSK-930)', () => {
  it('defaults to legacy; ?feed=kit or the preference opts into the kit panel; the query wins', () => {
    expect(DEFAULT_FEED_ENGINE).toBe('legacy')
    expect(resolveFeedEngine('', null)).toBe('legacy')
    expect(resolveFeedEngine('?feed=kit', null)).toBe('kit')
    expect(resolveFeedEngine('', 'kit')).toBe('kit')
    expect(resolveFeedEngine('?feed=legacy', null)).toBe('legacy')
    expect(resolveFeedEngine('', 'legacy')).toBe('legacy')
    expect(resolveFeedEngine('?feed=kit', 'legacy')).toBe('kit')
  })
})

describe('AppSync reconnect policy comes from the kit', () => {
  it('keeps the values the enceladus engine shipped with (500ms..30s, 12 attempts, 15s sweep, 300s timeout)', () => {
    expect([BACKOFF_BASE_MS, BACKOFF_CAP_MS, MAX_AUTO_RECONNECT_ATTEMPTS, LIVENESS_CHECK_INTERVAL_MS, DEFAULT_CONNECTION_TIMEOUT_MS]).toEqual([500, 30000, 12, 15000, 300000])
  })
  it('backoffDelay doubles from 500ms with 50-100% jitter and caps at 30s', () => {
    expect(backoffDelay(0, { random: () => 1 })).toBe(500)
    expect(backoffDelay(0, { random: () => 0 })).toBe(250)
    expect(backoffDelay(3, { random: () => 1 })).toBe(4000)
    expect(backoffDelay(20, { random: () => 1 })).toBe(30000)
  })
})
