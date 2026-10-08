import { describe, expect, it } from 'vitest'
import {
  APP_SHELL_NETWORK_TIMEOUT_SECONDS,
  WORKBOX_STRATEGY_MAP,
} from './workboxStrategies'

describe('WORKBOX_STRATEGY_MAP (B67 AC-17)', () => {
  it('defines the eight strategy entries', () => {
    expect(WORKBOX_STRATEGY_MAP).toHaveLength(8)
  })

  it('covers CacheFirst, StaleWhileRevalidate, NetworkFirst, NetworkOnly, app-layer queue', () => {
    const handlers = WORKBOX_STRATEGY_MAP.map((e) => e.handler)
    expect(handlers).toContain('CacheFirst')
    expect(handlers).toContain('StaleWhileRevalidate')
    expect(handlers.filter((h) => h.startsWith('NetworkFirst'))).toHaveLength(2)
    expect(handlers).toContain('NetworkOnly')
    // ENC-TSK-N04 (B67 AC-18): mutation queue+replay moved to the app layer;
    // a SW-level BackgroundSync on the same routes would double-replay.
    expect(handlers).toContain('NetworkOnly+AppLayerQueue')
  })

  it('serves the feed corpus and delta NetworkOnly (ENC-TSK-Q33)', () => {
    const feedSync = WORKBOX_STRATEGY_MAP.find((e) => e.id === 'feed-sync')
    expect(feedSync?.handler).toBe('NetworkOnly')
    expect(feedSync?.routes).toContain('/api/v1/feed/corpus')
    expect(feedSync?.routes).toContain('/api/v1/feed/delta')
  })

  it('uses 3s app-shell network timeout per DOC-E470AC8CE9A8', () => {
    expect(APP_SHELL_NETWORK_TIMEOUT_SECONDS).toBe(3)
  })
})
