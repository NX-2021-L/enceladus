import { queryOptions } from '@tanstack/react-query'
import { fetchHybridGraphsearch, GraphUnavailableError } from './client'
import type { HybridSearchParams } from '../types/search'

/** Stable key namespace for hybrid graphsearch reads (ENC-TSK-L22). */
export const searchKeys = {
  all: ['search'] as const,
  hybrid: (params: HybridSearchParams) =>
    [
      'search',
      'hybrid',
      {
        projectId: params.projectId,
        query: params.query ?? '',
        anchorRecordId: params.anchorRecordId ?? '',
        recordType: params.recordType ?? '',
        topN: params.topN ?? 20,
        includeBelowThreshold: params.includeBelowThreshold ?? false,
      },
    ] as const,
}

export const hybridSearchQueryOptions = (params: HybridSearchParams) =>
  queryOptions({
    queryKey: searchKeys.hybrid(params),
    queryFn: ({ signal }) => fetchHybridGraphsearch(params, { signal }),
    staleTime: 30_000,
    // Hybrid is enrichment — never retry aggressively; local tier stands alone.
    retry: (failureCount, error) => {
      if (error instanceof GraphUnavailableError) return false
      return failureCount < 1
    },
  })
