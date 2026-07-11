import { useQuery } from '@tanstack/react-query'
import { hybridSearchQueryOptions } from '../api/searchQueryOptions'
import { searchLocalKeyword } from './localKeywordSearch'
import { mergeSearchResults } from './mergeSearchResults'
import type { HybridSearchParams, LocalSearchRecord, TieredSearchSnapshot } from '../types/search'

/**
 * Two-tier search hook (ENC-TSK-L22 / FTR-127 AC-14):
 *   - Tier `local` paints synchronously from the provided corpus.
 *   - Tier `hybrid` loads async via the live graphsearch endpoint and merges in
 *     without blocking the local result set.
 */
export function useTieredSearch(
  params: HybridSearchParams,
  corpus: LocalSearchRecord[],
): TieredSearchSnapshot {
  const localHits = searchLocalKeyword(corpus, params.query ?? '')

  const hybridEnabled =
    Boolean(params.projectId) &&
    Boolean((params.query ?? '').trim() || params.anchorRecordId)

  const hybridQuery = useQuery({
    ...hybridSearchQueryOptions(params),
    enabled: hybridEnabled,
  })

  const merged = mergeSearchResults(localHits, hybridQuery.data, params.projectId)

  return {
    hits: merged.hits,
    localCount: merged.localCount,
    hybridCount: merged.hybridCount,
    hybridPending: hybridEnabled && hybridQuery.isFetching,
    hybridError: hybridQuery.error instanceof Error ? hybridQuery.error : null,
    signalAvailability: hybridQuery.data?.signal_availability,
    summary: hybridQuery.data?.summary,
  }
}
