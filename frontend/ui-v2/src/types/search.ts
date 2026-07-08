import type { RecordType } from './records'

/** Client-side instant tier (keyword/facet over local corpus). */
export type SearchTier = 'local' | 'hybrid'

export interface HybridSearchParams {
  projectId: string
  query?: string
  anchorRecordId?: string
  recordType?: RecordType
  topN?: number
  includeBelowThreshold?: boolean
}

export interface HybridGraphsearchNode {
  record_id: string
  project_id?: string
  title?: string
  status?: string
  _labels?: string[]
  [key: string]: unknown
}

export interface HybridGraphsearchResponse {
  success: boolean
  nodes: HybridGraphsearchNode[]
  edges: unknown[]
  paths: unknown[]
  summary: string
  query_cypher: string
  duration_ms: number
  signal_availability?: { vector: boolean; graph: boolean; keyword: boolean }
  graph_algorithm?: string
  rrf_k?: number
  per_node_fusion?: Record<
    string,
    {
      fused_rank?: number
      fused_score?: number
      per_signal_ranks?: Record<string, number>
      final_rank?: number
      final_score?: number
    }
  >
  fallback_hint?: string
}

export interface SearchResultHit {
  recordId: string
  recordType: RecordType
  projectId: string
  title: string
  status?: string
  /** ENC-FTR-130 Band-B: task/issue priority (e.g. 'P0'), when known. */
  priority?: string
  /** ENC-FTR-130 Band-B: tracker checkout_state (e.g. 'checked_out'), when known. */
  checkoutState?: string
  tier: SearchTier
  fusion?: HybridGraphsearchResponse['per_node_fusion'] extends Record<string, infer V>
    ? V
    : never
}

/** Minimal row the local keyword tier searches (feed snapshot, cache index, etc.). */
export interface LocalSearchRecord {
  recordId: string
  recordType: RecordType
  projectId: string
  title: string
  status?: string
  /** ENC-FTR-130 Band-B: task/issue priority (e.g. 'P0'), when known. */
  priority?: string
  /** ENC-FTR-130 Band-B: tracker checkout_state (e.g. 'checked_out'), when known. */
  checkoutState?: string
}

export interface TieredSearchSnapshot {
  /** Merged view — local hits first, then hybrid-only additions. */
  hits: SearchResultHit[]
  localCount: number
  hybridCount: number
  hybridPending: boolean
  hybridError: Error | null
  signalAvailability?: HybridGraphsearchResponse['signal_availability']
  summary?: string
}
