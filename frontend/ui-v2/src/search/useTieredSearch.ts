import { useHybridSearch } from '@io-kit/search/react'
import type { DegradedEntry, SearchHit, SignalAvailability } from '@io-kit/search'
import { hostSearchSource } from './enceladusSearchSource'
import { kitHitsToResultHits, localToResult } from './kitHits'
import { searchLocalKeyword } from './localKeywordSearch'
import type { HybridSearchParams, LocalSearchRecord, TieredSearchSnapshot } from '../types/search'

/** graphsearch p50 is 1.5-9 s; the kit default hard cap (1.5 s) would always read as "server down". */
const HYBRID_HARD_CAP_MS = 15_000

/**
 * Two-tier search hook (ENC-TSK-L22 / FTR-127 AC-14), now on @io-kit/search (DVP-TSK-921):
 *   - tier `local` paints synchronously from the provided corpus;
 *   - tier `hybrid` comes from the kit's useHybridSearch over the enceladus graphsearch SearchSource; hybrid order
 *     wins, ids are de-duplicated, local-only hits follow (kit mergeTiers), and the response's per-signal
 *     evidence and degraded signals are surfaced for the UI.
 * A blank query is browse/filter mode (Home deep links): the local tier returns the whole corpus, as before.
 */
export function useTieredSearch(params: HybridSearchParams, corpus: LocalSearchRecord[]): TieredSearchSnapshot {
  const q = (params.query ?? '').trim()
  const filters: Record<string, string> = { project_id: params.projectId }
  if (params.recordType) filters.record_type = params.recordType
  if (params.anchorRecordId) filters.anchor_record_id = params.anchorRecordId
  if (params.includeBelowThreshold) filters.include_below_threshold = 'true'

  const state = useHybridSearch({
    source: hostSearchSource,
    q,
    filters,
    ...(params.topN != null ? { limit: params.topN } : {}),
    hardCapMs: HYBRID_HARD_CAP_MS,
    local: (req) => searchLocalKeyword(corpus, req.q).map(localToResult),
  })

  if (!q) {
    const all = searchLocalKeyword(corpus, '')
    return { hits: all, localCount: all.length, hybridCount: 0, hybridPending: false, hybridError: null, degraded: [], serverDown: false, evidenceById: new Map() }
  }

  const hits = kitHitsToResultHits(state.hits, params.projectId, corpus)
  const availability: SignalAvailability | undefined = state.availability
  return {
    hits,
    localCount: state.hits.length - state.hits.filter((h) => h.tier === 'hybrid').length,
    hybridCount: state.hits.filter((h) => h.tier === 'hybrid').length,
    hybridPending: state.status === 'local',
    hybridError: state.error ?? null,
    signalAvailability: availability
      ? { keyword: availability.keyword === 'available', vector: availability.vector === 'available', graph: availability.graph === 'available' }
      : undefined,
    availability,
    degraded: state.degraded as DegradedEntry[],
    serverDown: state.serverDown,
    evidenceById: new Map(state.hits.map((h: SearchHit) => [h.id, h.evidence])),
  }
}
