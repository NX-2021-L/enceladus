/**
 * B67 AC-17 — canonical Workbox strategy map (DOC-E470AC8CE9A8 §7.1).
 * src/offline/runtimeCaching.ts must stay aligned with these entries.
 *
 * ENC-TSK-Q33 (ENC-ISS-830): the feed corpus and delta moved off
 * StaleWhileRevalidate. A service worker answers before fetch's
 * `cache: 'no-store'` applies, so SWR handed the corpus seed the previous
 * visit's first page — exactly the newest records. They are NetworkOnly now
 * (IndexedDB tier1 is the offline tier); other feed reads are NetworkFirst.
 */
export const WORKBOX_STRATEGY_MAP = [
  { id: 'static-assets', handler: 'CacheFirst', routes: 'Vite content-hashed JS/CSS (precache + media)' },
  { id: 's3-payloads', handler: 'CacheFirst', routes: '/mobile/v1/reference/*' },
  { id: 'feed-sync', handler: 'NetworkOnly', routes: '/api/v1/feed/corpus*, /api/v1/feed/delta*' },
  {
    id: 'feed-api',
    handler: 'NetworkFirst',
    routes: '/api/v1/feed* (other reads), /feed/*',
    timeoutSeconds: 3,
  },
  { id: 'mobile-feed', handler: 'StaleWhileRevalidate', routes: '/mobile/v1/*.json' },
  {
    id: 'record-detail',
    handler: 'NetworkFirst',
    routes: 'GET /api/v1/tracker/*/{type}/{id}, GET /api/v1/documents/*',
    timeoutSeconds: 5,
  },
  { id: 'auth', handler: 'NetworkOnly', routes: '/api/v1/auth*, /callback, /mobile/v1/auth*' },
  {
    // ENC-TSK-N04 (B67 AC-18): queue+replay for this route class is the
    // app-layer mutationQueue (If-Match aware, UI pendingCount), NOT Workbox
    // BackgroundSync — a SW-level queue on the same routes would double-replay.
    id: 'mutations',
    handler: 'NetworkOnly+AppLayerQueue',
    routes: 'PATCH|POST|DELETE /api/v1/tracker/*, /api/v1/documents/*',
  },
] as const

export const APP_SHELL_NETWORK_TIMEOUT_SECONDS = 3

export type WorkboxStrategyId = (typeof WORKBOX_STRATEGY_MAP)[number]['id']
