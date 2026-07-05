/**
 * Typed queryOptions factories for GET /api/v1/feed/corpus (ENC-TSK-L23),
 * reused by the Home dashboard (ENC-TSK-L30) to source "most recent per
 * type" + "recent documents" + facet counts without inventing a new backend
 * endpoint.
 *
 * `facets` in the corpus response are computed over the FULL filtered set
 * (see backend/lambda/feed_query/corpus.py::paginate_corpus) — before the
 * `limit` slice is applied — so a `limit: 1` request is enough to get
 * dashboard-wide counts per record_type / status / priority / project_id
 * cheaply. A `record_type` + `limit: 1` + `sort: 'updated_at_desc'` request
 * gets the single most-recent record of that type, independent of how deep
 * that type sits in the global recency ordering (so it stays correct even
 * once the corpus outgrows the MAX_LIMIT=200 page window).
 */

import { queryOptions } from '@tanstack/react-query'
import { API_BASE, fetchFeedCorpusPage } from './client'
import type { FeedCorpusPage } from '../sync/types'

export interface FeedCorpusQueryParams {
  cursor?: string
  limit?: number
  sort?: string
  q?: string
}

function paramsKey(params: Record<string, string | number | undefined>) {
  return Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k] ?? ''}`)
}

export const feedCorpusKeys = {
  all: ['feed', 'corpus'] as const,
  page: (params: Record<string, string | number | undefined>) =>
    ['feed', 'corpus', ...paramsKey(params)] as const,
}

/** Whole-corpus page (used today by ENC-TSK-L23 consumers); kept here too so
 * the Home dashboard can request a cheap `limit: 1` page purely for its
 * `facets` (dashboard-wide counts per record_type/status/priority). */
export const feedCorpusQueryOptions = (params: FeedCorpusQueryParams = {}) =>
  queryOptions<FeedCorpusPage>({
    queryKey: feedCorpusKeys.page({ ...params }),
    queryFn: ({ signal }) => fetchFeedCorpusPage(params, { signal }),
    staleTime: 60 * 1000,
  })

/**
 * `fetchFeedCorpusPage` (src/api/client.ts) doesn't expose `record_type`
 * today — ENC-TSK-L23 shipped without it since its Feed route filters
 * client-side. The backend query parser already accepts it
 * (`corpus.py::parse_corpus_query` / `_matches_filters`), so this factory
 * threads it through the querystring directly rather than widening the
 * shared client function signature mid-parallel-build (client.ts is a hot
 * file for the other L2x tasks too).
 */
export const feedCorpusByTypeQueryOptions = (
  recordType: string,
  params: Omit<FeedCorpusQueryParams, 'q'> = {},
) =>
  queryOptions<FeedCorpusPage>({
    queryKey: feedCorpusKeys.page({ ...params, recordType }),
    queryFn: async ({ signal }) => {
      const qs = new URLSearchParams()
      qs.set('record_type', recordType)
      qs.set('limit', String(params.limit ?? 1))
      qs.set('sort', params.sort ?? 'updated_at_desc')
      const res = await fetch(`${API_BASE}/feed/corpus?${qs.toString()}`, {
        signal,
        credentials: 'include',
        cache: 'no-store',
        headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest' },
      })
      if (res.status === 401) {
        const { SessionExpiredError } = await import('./client')
        throw new SessionExpiredError()
      }
      if (!res.ok) throw new Error(`Request failed (${res.status}): feed/corpus`)
      return (await res.json()) as FeedCorpusPage
    },
    staleTime: 60 * 1000,
  })
