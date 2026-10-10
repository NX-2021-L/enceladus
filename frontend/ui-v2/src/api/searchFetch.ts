/**
 * searchFetch.ts -- DVP-TSK-921: the transport behind the @io-kit/search enceladus SearchSource. The kit
 * adapter issues GET /api/v1/tracker/graphsearch itself, so the request lives under src/api like every read.
 * Same-origin and cookie-authenticated (Cognito cookie).
 */
export type SearchFetch = (
  url: string,
  init: { signal?: AbortSignal; headers?: Record<string, string> },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>

export const browserSearchFetch: SearchFetch = (url, init) =>
  fetch(url, {
    signal: init.signal,
    credentials: 'include',
    cache: 'no-store',
    headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest', ...init.headers },
  })
