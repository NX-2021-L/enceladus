import { APP_SHELL_NETWORK_TIMEOUT_SECONDS } from './workboxStrategies'

/**
 * Workbox runtime-caching routes, consumed by vite.config.ts (VitePWA
 * generateSW). Kept here so the route table is unit-testable: Workbox answers
 * a request with the FIRST route whose urlPattern matches, and tests assert
 * that resolution directly (runtimeCaching.test.ts).
 *
 * generateSW serializes every urlPattern with Function#toString into sw.js,
 * so each matcher must be a self-contained arrow function that references
 * nothing outside its own parameters.
 */

export type RuntimeCachingHandler = 'CacheFirst' | 'NetworkFirst' | 'NetworkOnly' | 'StaleWhileRevalidate'

export interface RuntimeCachingRoute {
  urlPattern: (context: { url: URL; request: Request }) => boolean
  handler: RuntimeCachingHandler
  method?: 'GET' | 'PATCH' | 'POST' | 'DELETE'
  options?: {
    cacheName?: string
    networkTimeoutSeconds?: number
    expiration?: { maxAgeSeconds?: number }
  }
}

/** ENC-TSK-Q33 (ENC-ISS-830): the pre-Q33 StaleWhileRevalidate cache for
 *  /api/v1/feed*. It served the corpus seed's fixed first-page URL from the
 *  PREVIOUS visit, so the newest records were always the ones missing. The
 *  service worker deletes it on activation (public/sw-feed-cache-cleanup.js). */
export const LEGACY_FEED_API_CACHE = 'feed-api'

/** NetworkFirst cache for the remaining /api/v1/feed* reads and /feed/ JSON. */
export const FEED_API_NETWORK_FIRST_CACHE = 'feed-api-network-first'

/** Script imported into the generated service worker (importScripts). */
export const SW_FEED_CACHE_CLEANUP_SCRIPT = 'sw-feed-cache-cleanup.js'

export const RUNTIME_CACHING: RuntimeCachingRoute[] = [
  {
    urlPattern: ({ request }) => request.destination === 'image' || request.destination === 'font',
    handler: 'CacheFirst',
    options: {
      cacheName: 'static-media',
      expiration: { maxAgeSeconds: 60 * 60 * 24 * 30 },
    },
  },
  {
    urlPattern: ({ request }) => request.mode === 'navigate',
    handler: 'NetworkFirst',
    options: {
      cacheName: 'app-shell',
      networkTimeoutSeconds: APP_SHELL_NETWORK_TIMEOUT_SECONDS,
    },
  },
  {
    // ENC-TSK-Q33: the corpus seed and delta heal must always reach the
    // network. fetch(..., { cache: 'no-store' }) does not bypass a service
    // worker, so any Workbox cache here re-serves an old snapshot. IndexedDB
    // tier1 (sync/idbStore.ts) is the offline tier for this data.
    urlPattern: ({ url }) =>
      url.pathname.startsWith('/api/v1/feed/corpus') || url.pathname.startsWith('/api/v1/feed/delta'),
    handler: 'NetworkOnly',
  },
  {
    urlPattern: ({ url }) => url.pathname.startsWith('/api/v1/feed') || url.pathname.startsWith('/feed/'),
    handler: 'NetworkFirst',
    options: {
      cacheName: FEED_API_NETWORK_FIRST_CACHE,
      networkTimeoutSeconds: APP_SHELL_NETWORK_TIMEOUT_SECONDS,
    },
  },
  {
    urlPattern: ({ url }) => url.pathname.startsWith('/mobile/v1/') && url.pathname.endsWith('.json'),
    handler: 'StaleWhileRevalidate',
    options: { cacheName: 'mobile-feed-swr' },
  },
  {
    urlPattern: ({ url }) => url.pathname.startsWith('/mobile/v1/reference/'),
    handler: 'CacheFirst',
    options: {
      cacheName: 's3-reference',
      expiration: { maxAgeSeconds: 60 * 60 * 24 * 7 },
    },
  },
  {
    urlPattern: ({ url, request }) =>
      request.method === 'GET' &&
      (Boolean(url.pathname.match(/^\/api\/v1\/tracker\/[^/]+\/(task|issue|feature|plan|lesson)\//)) ||
        (url.pathname.startsWith('/api/v1/documents/') && !url.pathname.includes('/search'))),
    handler: 'NetworkFirst',
    options: {
      cacheName: 'record-detail',
      networkTimeoutSeconds: 5,
    },
  },
  {
    urlPattern: ({ url }) =>
      url.pathname.startsWith('/api/v1/auth') ||
      url.pathname.includes('/callback') ||
      url.pathname.startsWith('/mobile/v1/auth'),
    handler: 'NetworkOnly',
  },
  {
    urlPattern: ({ url }) => url.pathname.startsWith('/api/v1/deploy/'),
    handler: 'NetworkOnly',
  },
  // ENC-TSK-N04 (B67 AC-18): mutations are NetworkOnly with NO Workbox
  // BackgroundSync. Offline queue+replay for tracker/document
  // mutations is owned by the app layer (src/offline/mutationQueue.ts
  // via patchTrackerRecord) — it is If-Match/revision-conflict aware
  // and drives the UI pendingCount, none of which a blind SW replay
  // can do. Keeping the SW-level queue alongside it would replay the
  // same mutation twice once the app layer queues on network failure.
  ...(['PATCH', 'POST', 'DELETE'] as const).map(
    (method): RuntimeCachingRoute => ({
      urlPattern: ({ url }) =>
        (url.pathname.startsWith('/api/v1/tracker/') || url.pathname.startsWith('/api/v1/documents/')) &&
        !url.pathname.includes('/graphsearch'),
      handler: 'NetworkOnly',
      method,
    }),
  ),
]
