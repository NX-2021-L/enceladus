import type { RecordType } from '../types/records'
import type {
  HybridGraphsearchNode,
  HybridGraphsearchResponse,
  SearchResultHit,
  SearchTier,
} from '../types/search'

const PREFIX_TO_TYPE: Record<string, RecordType> = {
  TSK: 'task',
  ISS: 'issue',
  FTR: 'feature',
  PLN: 'plan',
  LSN: 'lesson',
  DOC: 'document',
}

export function inferRecordTypeFromNode(node: HybridGraphsearchNode): RecordType {
  for (const label of node._labels ?? []) {
    const lower = label.toLowerCase()
    if (['task', 'issue', 'feature', 'plan', 'lesson', 'document'].includes(lower)) {
      return lower as RecordType
    }
  }
  if (node.record_id.startsWith('DOC-')) return 'document'
  const mid = node.record_id.split('-')[1]
  return (mid && PREFIX_TO_TYPE[mid]) ?? 'task'
}

export function hybridNodesToHits(
  projectId: string,
  response: HybridGraphsearchResponse,
): SearchResultHit[] {
  const fusion = response.per_node_fusion ?? {}
  return (response.nodes ?? []).map((node) => {
    const recordId = node.record_id
    return {
      recordId,
      recordType: inferRecordTypeFromNode(node),
      projectId: node.project_id ?? projectId,
      title: node.title ?? recordId,
      status: typeof node.status === 'string' ? node.status : undefined,
      tier: 'hybrid' as SearchTier,
      fusion: fusion[recordId],
    }
  })
}

/**
 * Merge local (instant) and hybrid (async) tiers without blocking the local
 * paint path. Local hits are preserved; hybrid adds unseen record_ids and
 * attaches fusion metadata when the same id appears in both tiers.
 */
export function mergeSearchResults(
  localHits: SearchResultHit[],
  hybridResponse: HybridGraphsearchResponse | undefined,
  projectId: string,
): { hits: SearchResultHit[]; localCount: number; hybridCount: number } {
  const hybridHits = hybridResponse ? hybridNodesToHits(projectId, hybridResponse) : []
  const byId = new Map<string, SearchResultHit>()

  for (const hit of localHits) {
    byId.set(hit.recordId, hit)
  }

  for (const hit of hybridHits) {
    const existing = byId.get(hit.recordId)
    if (existing) {
      byId.set(hit.recordId, {
        ...existing,
        fusion: hit.fusion,
        // Keep tier=local for rows that painted instantly; fusion enriches them.
      })
    } else {
      byId.set(hit.recordId, hit)
    }
  }

  const hits = [...byId.values()]
  const localCount = hits.filter((h) => h.tier === 'local').length
  const hybridCount = hybridHits.length
  return { hits, localCount, hybridCount }
}
