import type { RecordType } from '../types/records'
import * as idb from './idbStore'
import { CorpusSearchIndex } from './searchIndex'
import { cacheKey, shouldAcceptVersion, versionSeqFromUpdatedAt } from './recordKey'
import type { FeedCorpusItem, Tier1Record, Tier2Record } from './types'
import { DEFAULT_CACHE_BUDGET } from './types'

const VALID_TYPES: RecordType[] = ['task', 'issue', 'feature', 'plan', 'lesson', 'document']

function normalizeRecordType(raw: string): RecordType | null {
  const value = raw.toLowerCase() as RecordType
  return VALID_TYPES.includes(value) ? value : null
}

export function corpusItemToTier1(item: FeedCorpusItem): Tier1Record | null {
  const recordType = normalizeRecordType(item.record_type)
  if (!recordType) return null
  const versionSeq = versionSeqFromUpdatedAt(item.updated_at)
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
    this.searchIndex.rebuild(rows.slice(0, this.budget.searchIndexMax))
    this.warmedAt = Date.now()
  }

  markWarmComplete(startedAt: number): void {
    this.warmedAt = Date.now()
    this.warmDurationMsValue = this.warmedAt - startedAt
  }

  async loadSearchSlice(): Promise<void> {
    const rows = await idb.listTier1(this.budget.searchIndexMax)
    this.searchIndex.rebuild(rows)
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
