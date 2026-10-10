import type { SearchHit, SearchResult } from '@io-kit/search'
import type { RecordType } from '../types/records'
import type { LocalSearchRecord, SearchResultHit } from '../types/search'
import { inferRecordTypeFromNode } from './mergeSearchResults'
import { rawNodeFor } from './enceladusSearchSource'

const RECORD_TYPES: ReadonlySet<string> = new Set(['task', 'issue', 'feature', 'plan', 'lesson', 'document'])

/** Local tier row -> the kit's SearchResult (keyword rank by position; vector and graph did not run). */
export function localToResult(hit: SearchResultHit, index: number): SearchResult {
  return {
    id: hit.recordId,
    type: hit.recordType,
    title: hit.title,
    snippet: '',
    per_signal_ranks: { keyword: index + 1, vector: null, graph: null },
    score: 0,
  }
}

/**
 * Kit hit (merged two-tier order, tier badge, per-signal evidence) -> the card model the Feed already renders.
 * Local rows keep their cached fields; hybrid-only rows take status/priority/updated_at from the raw graphsearch node.
 */
export function kitHitsToResultHits(
  hits: SearchHit[],
  projectId: string,
  local: LocalSearchRecord[],
): SearchResultHit[] {
  const byId = new Map(local.map((r) => [r.recordId, r]))
  return hits.map((h) => {
    const row = byId.get(h.id)
    const node = rawNodeFor(h.id)
    const recordType: RecordType =
      row?.recordType ??
      (RECORD_TYPES.has(h.type) ? (h.type as RecordType) : inferRecordTypeFromNode({ record_id: h.id, _labels: [h.type] }))
    const ranks: Record<string, number> = {}
    for (const e of h.evidence) if (e.rank !== null) ranks[e.signal] = e.rank
    return {
      recordId: h.id,
      recordType,
      projectId: row?.projectId ?? node?.project_id ?? projectId,
      title: row?.title ?? h.title,
      status: row?.status ?? node?.status,
      priority: row?.priority ?? node?.priority,
      checkoutState: row?.checkoutState,
      updatedAt: row?.updatedAt ?? node?.updated_at,
      tier: h.tier,
      ...(h.tier === 'hybrid' ? { fusion: { per_signal_ranks: ranks, final_score: h.fusedScore } } : {}),
    }
  })
}
