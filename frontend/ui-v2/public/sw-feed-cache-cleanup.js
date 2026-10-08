// ENC-TSK-Q33 (ENC-ISS-830): imported into the generated service worker via
// workbox.importScripts (vite.config.ts). Before Q33 every /api/v1/feed*
// response was cached StaleWhileRevalidate in 'feed-api', so the corpus seed's
// first page always came from the previous visit. Corpus and delta are now
// NetworkOnly; drop the stale snapshot the old worker left behind.
self.addEventListener('activate', (event) => {
  event.waitUntil(caches.delete('feed-api'))
})
