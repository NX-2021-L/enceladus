import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  LEGACY_FEED_API_CACHE,
  RUNTIME_CACHING,
  SW_FEED_CACHE_CLEANUP_SCRIPT,
  type RuntimeCachingRoute,
} from './runtimeCaching'
import { WORKBOX_STRATEGY_MAP } from './workboxStrategies'

const ORIGIN = 'https://enceladus.jreese.net'

/** Workbox resolves a request with the FIRST route whose matcher passes. */
function resolveRoute(pathname: string, method = 'GET'): RuntimeCachingRoute | undefined {
  const url = new URL(pathname, ORIGIN)
  const request = { method, mode: 'cors', destination: '' } as unknown as Request
  return RUNTIME_CACHING.find(
    (route) => (route.method ?? 'GET') === method && route.urlPattern({ url, request }),
  )
}

describe('RUNTIME_CACHING (ENC-TSK-Q33 / ENC-ISS-830)', () => {
  it.each([
    '/api/v1/feed/corpus?limit=200',
    '/api/v1/feed/corpus?cursor=eyJzb3J0X3ZhbHVlIjoiMjAyNi0xMC0wOCJ9&limit=200',
    '/api/v1/feed/corpus?limit=1',
    '/api/v1/feed/delta?since=0',
    '/api/v1/feed/delta?since=5101&doc_since=185',
  ])('never answers %s from a Workbox cache', (pathname) => {
    const route = resolveRoute(pathname)
    expect(route?.handler).toBe('NetworkOnly')
    expect(route?.handler).not.toBe('StaleWhileRevalidate')
    expect(route?.handler).not.toBe('CacheFirst')
  })

  it('serves the other feed reads network-first, never from the legacy SWR cache', () => {
    const route = resolveRoute('/api/v1/feed')
    expect(route?.handler).toBe('NetworkFirst')
    expect(route?.options?.cacheName).not.toBe(LEGACY_FEED_API_CACHE)
  })

  it('has no StaleWhileRevalidate route matching /api/v1/feed', () => {
    const url = new URL('/api/v1/feed/corpus', ORIGIN)
    const request = { method: 'GET', mode: 'cors', destination: '' } as unknown as Request
    const swrMatches = RUNTIME_CACHING.filter(
      (route) => route.handler === 'StaleWhileRevalidate' && route.urlPattern({ url, request }),
    )
    expect(swrMatches).toHaveLength(0)
  })

  it('keeps mutations NetworkOnly', () => {
    expect(resolveRoute('/api/v1/tracker/enceladus/task/ENC-TSK-1', 'PATCH')?.handler).toBe('NetworkOnly')
    expect(resolveRoute('/api/v1/documents/DOC-1', 'POST')?.handler).toBe('NetworkOnly')
  })

  it('matchers are self-contained so generateSW can serialize them', () => {
    // generateSW inlines each urlPattern via Function#toString; a matcher that
    // closes over a module identifier would throw ReferenceError in sw.js.
    for (const route of RUNTIME_CACHING) {
      const source = route.urlPattern.toString()
      expect(source).not.toMatch(/\b(LEGACY_FEED_API_CACHE|FEED_API_NETWORK_FIRST_CACHE|APP_SHELL_NETWORK_TIMEOUT_SECONDS)\b/)
    }
  })

  it('agrees with the canonical strategy map for the feed routes', () => {
    const feedSync = WORKBOX_STRATEGY_MAP.find((entry) => entry.id === 'feed-sync')
    expect(resolveRoute('/api/v1/feed/corpus')?.handler).toBe(feedSync?.handler)
    const feedApi = WORKBOX_STRATEGY_MAP.find((entry) => entry.id === 'feed-api')
    expect(resolveRoute('/api/v1/feed')?.handler).toBe(feedApi?.handler)
  })

  it('ships a cleanup script that deletes the legacy feed-api cache on activate', () => {
    const script = readFileSync(
      path.resolve(__dirname, '../../public', SW_FEED_CACHE_CLEANUP_SCRIPT),
      'utf-8',
    )
    expect(script).toContain("addEventListener('activate'")
    expect(script).toContain(`caches.delete('${LEGACY_FEED_API_CACHE}')`)
  })
})
