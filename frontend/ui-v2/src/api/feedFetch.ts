/**
 * feedFetch.ts -- DVP-TSK-919: the transport behind the @io-kit/feed FeedSource. The kit engine owns paging
 * and caching, so the source issues its requests directly; they live under src/api like every other read.
 * Same-origin and cookie-authenticated (the feed endpoints sit behind the Cognito cookie).
 */
export interface FetchLike {
  (url: string, init?: { signal?: AbortSignal }): Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>
}

// eslint-disable-next-line no-restricted-globals -- kit FeedSource transport (see file comment)
export const browserFetch: FetchLike = (url, init) =>
  fetch(url, {
    signal: init?.signal,
    credentials: 'include',
    cache: 'no-store',
    headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest' },
  })
