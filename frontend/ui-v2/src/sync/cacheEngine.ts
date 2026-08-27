import type { RecordType } from '../types/records'
import * as idb from './idbStore'
import { CorpusSearchIndex } from './searchIndex'
import { cacheKey, shouldAcceptVersion, versionSeqFromItem, versionSeqFromUpdatedAt } from './recordKey'
import type { FeedCorpusItem, Tier1Record, Tier2Record } from './types'
import { DEFAULT_CACHE_BUDGET } from './types'

const VALID_TYPES: RecordType[] = ['task', 'issue', 'feature', 'plan', 'lesson', 'document']

// ENC-ISS-711: the searchable index must be populated by recency, not by the
// IndexedDB primary-key order (`projectId:recordId`) that `listTier1` returns.
// The corpus is far larger than one project (measured: 7940 rows, 4417 of them
// enceladus), so a key-order slice fills the budget with alphabetically-early
// projects and enceladus DOC-* documents and never reaches `enceladus:ENC-*`
// records at all -- hiding a whole contiguous recency band. Order by updated_at
// descending so, whatever the cap, the most-recently-updated records are kept.
function updatedAtEpoch(row: Tier1Record): number {
  const parsed = row.updatedAt ? Date.parse(row.updatedAt) : NaN
  return Number.isNaN(parsed) ? -Infinity : parsed
}

function sortByRecencyDesc(rows: Tier1Record[]): Tier1Record[] {
  return [...rows].sort((a, b) => {
    const ta = updatedAtEpoch(a)
    const tb = updatedAtEpoch(b)
    if (ta === tb) return 0
    return tb > ta ? 1 : -1
  })
}

function normalizeRecordType(raw: string): RecordType | null {
  const value = raw.toLowerCase() as RecordType
  return VALID_TYPES.includes(value) ? value : null
}

export function corpusItemToTier1(item: FeedCorpusItem): Tier1Record | null {
  const recordType = normalizeRecordType(item.record_type)
  if (!recordType) return null
  const versionSeq = versionSeqFromItem(item)
  return {
    projectId: item.project_id || (recordType === 'document' ? 'global' : 'enceladus'),
    recordId: item.record_id,
    recordType,
    title: item.title || item.record_id,
    status: typeof item.attrs?.status === 'string' ? item.attrs.status : undefined,
    priority: typeof item.attrs?.priority === 'string' ? item.attrs.priority : undefined,
    updatedAt: item.updated_at ?? null,
    source: item.source,
    recordKey: item.record_key,
    versionSeq,
    attrs: item.attrs ?? {},
  }
}

export class CacheEngine {
  readonly searchIndex: CorpusSearchIndex
  private warmedAt: number | null = null
  private warmDurationMsValue: number | null = null

  constructor(private readonly budget = DEFAULT_CACHE_BUDGET) {
    this.searchIndex = new CorpusSearchIndex(budget.searchIndexMax)
  }

  get isWarm(): boolean {
    return this.warmedAt !== null
  }

  get warmDurationMs(): number | null {
    return this.warmDurationMsValue
  }

  async upsertTier1(record: Tier1Record): Promise<void> {
    if (await idb.hasTombstone(record.recordKey)) return
    const existing = await idb.getTier1(record.projectId, record.recordId)
    if (existing && !shouldAcceptVersion(existing.versionSeq, record.versionSeq)) return
    await idb.putTier1(record)
    this.searchIndex.upsert(record)
  }

  async upsertTier2(
    projectId: string,
    recordId: string,
    body: unknown,
    versionSeq: string,
  ): Promise<void> {
    const existing = await idb.getTier2(projectId, recordId)
    if (existing && !shouldAcceptVersion(existing.versionSeq, versionSeq)) return
    await idb.putTier2({
      projectId,
      recordId,
      body,
      versionSeq,
      touchedAt: Date.now(),
    })
    await this.evictTier2IfNeeded()
  }

  async getTier2Body(projectId: string, recordId: string): Promise<unknown | null> {
    const row = await idb.getTier2(projectId, recordId)
    if (!row) return null
    await idb.putTier2({ ...row, touchedAt: Date.now() })
    return row.body
  }

  async markTombstone(recordKey: string, recordId: string): Promise<void> {
    await idb.putTombstone({ recordKey, deletedAt: Date.now() })
    this.searchIndex.remove(recordId)
  }

  async ingestCorpusPage(items: FeedCorpusItem[]): Promise<number> {
    let count = 0
    for (const item of items) {
      const tier1 = corpusItemToTier1(item)
      if (!tier1) continue
      await this.upsertTier1(tier1)
      count += 1
    }
    return count
  }

  async finalizeWarm(): Promise<void> {
    const rows = await idb.listTier1(this.budget.tier1Max)
    if (rows.length > this.budget.searchIndexMax) {
      // ENC-ISS-711: never truncate silently -- a future corpus that outgrows
      // the budget would otherwise reintroduce a hidden band with no signal.
      console.warn(
        `[cacheEngine] searchIndex truncated: ${rows.length} tier1 rows exceed ` +
          `searchIndexMax=${this.budget.searchIndexMax}; keeping the most-recent ${this.budget.searchIndexMax}`,
      )
    }
    this.searchIndex.rebuild(sortByRecencyDesc(rows))
    this.warmedAt = Date.now()
  }

  markWarmComplete(startedAt: number): void {
    this.warmedAt = Date.now()
    this.warmDurationMsValue = this.warmedAt - startedAt
  }

  async loadSearchSlice(): Promise<void> {
    // ENC-ISS-711: read the full tier1 set (not just searchIndexMax rows in
    // key order) so the recency sort selects the most-recent records before the
    // rebuild applies the cap. Reading only searchIndexMax rows here would drop
    // the ENC-* tail before it could be considered.
    const rows = await idb.listTier1(this.budget.tier1Max)
    this.searchIndex.rebuild(sortByRecencyDesc(rows))
    if (rows.length > 0 && !this.warmedAt) {
      this.warmedAt = Date.now()
    }
  }

  private async evictTier2IfNeeded(): Promise<void> {
    const rows = await idb.listTier2()
    if (rows.length <= this.budget.tier2Max) return
    const sorted = [...rows].sort((a, b) => a.touchedAt - b.touchedAt)
    const evictCount = rows.length - this.budget.tier2Max
    for (const row of sorted.slice(0, evictCount)) {
      await idb.deleteTier2(row.projectId, row.recordId)
    }
  }
}

let singleton: CacheEngine | null = null

export function getCacheEngine(): CacheEngine {
  if (!singleton) singleton = new CacheEngine()
  return singleton
}

export function resetCacheEngineForTests(): void {
  singleton = null
  idb.resetMemoryStoreForTests()
}

export function tier1FromFeedEvent(input: {
  recordId: string
  recordType: string
  projectId: string
  title: string
  status?: string
  updatedAt?: string | null
}): Tier1Record | null {
  const recordType = normalizeRecordType(input.recordType)
  if (!recordType) return null
  const projectId = input.projectId || (recordType === 'document' ? 'global' : 'enceladus')
  const recordKey =
    recordType === 'document'
      ? `document::${input.recordId}`
      : `tracker:${projectId}:${input.recordId}`
  return {
    projectId,
    recordId: input.recordId,
    recordType,
    title: input.title,
    status: input.status,
    updatedAt: input.updatedAt ?? null,
    source: recordType === 'document' ? 'document' : 'tracker',
    recordKey,
    versionSeq: versionSeqFromUpdatedAt(input.updatedAt),
    attrs: { status: input.status },
  }
}
