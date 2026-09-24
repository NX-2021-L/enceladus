import type { RecordType } from '../types/records'

/** Minimal Tier-1 index row keyed by (project_id, record_id). */
export interface Tier1Record {
  projectId: string
  recordId: string
  recordType: RecordType
  title: string
  status?: string
  priority?: string
  updatedAt?: string | null
  source: 'tracker' | 'document'
  recordKey: string
  versionSeq: string
  attrs: Record<string, unknown>
}

/** Tier-2 full-body cache entry with LRU metadata. */
export interface Tier2Record {
  projectId: string
  recordId: string
  body: unknown
  versionSeq: string
  touchedAt: number
}

export interface TombstoneRecord {
  recordKey: string
  deletedAt: number
}

export interface CacheBudget {
  tier1Max: number
  tier2Max: number
  searchIndexMax: number
}

// ENC-ISS-711: the prior 5k/2k budgets were smaller than a single project's
// corpus (enceladus alone is ~4.4k records; all projects ~7.9k), so the search
// index could never hold the full working set and dropped a recency band. The
// index rows are lightweight (id/type/title/status/updatedAt) -- ~8k of them is
// a few MB in memory -- so size the budget above the live corpus with headroom.
export const DEFAULT_CACHE_BUDGET: CacheBudget = {
  tier1Max: 20_000,
  tier2Max: 500,
  searchIndexMax: 20_000,
}

export interface FeedCorpusItem {
  record_id: string
  record_type: string
  project_id: string
  title: string
  updated_at?: string | null
  source: 'tracker' | 'document'
  record_key: string
  version_seq?: number
  attrs?: Record<string, unknown>
}

export interface FeedDeltaTombstone {
  record_key: string
  record_id: string
  record_type: string
  project_id: string
  version_seq: number
}

export interface FeedDeltaPage {
  success: boolean
  since: number
  latest_version_seq: number
  items: FeedCorpusItem[]
  tombstones: FeedDeltaTombstone[]
}

export interface FeedCorpusPage {
  success: boolean
  items: FeedCorpusItem[]
  next_cursor: string | null
  facets: Record<string, Record<string, number>>
  total_matches: number
}
