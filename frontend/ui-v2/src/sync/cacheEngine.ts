import type { RecordType } from '../types/records'
import * as idb from './idbStore'
import { CorpusSearchIndex } from './searchIndex'
import {
  isStrictlyNewerVersion,
  shouldAcceptRecord,
  shouldAcceptVersion,
  versionSeqFromItem,
  versionSeqFromUpdatedAt,
} from './recordKey'
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

// ENC-TSK-Q34: document_api's version_seq counter row in DOCUMENTS_TABLE. Pre-Q34
// corpora served it as a phantom document, and clients that cached it keep it in
// IndexedDB because a seed only upserts. It is never a record.
export const DOCUMENT_COUNTER_SENTINEL_ID = '__COUNTER__VERSION_SEQ__'

export function corpusItemToTier1(item: FeedCorpusItem): Tier1Record | null {
  if (item.record_id === DOCUMENT_COUNTER_SENTINEL_ID) return null
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
    const tombstone = await idb.getTombstone(record.recordKey)
    if (tombstone) {
      // ENC-TSK-Q34: a versioned tombstone (e.g. an archived document) yields
      // only to a strictly newer version of the same record, so an
      // un-archived document can come back. Unversioned tombstones are final.
      if (!tombstone.versionSeq || !isStrictlyNewerVersion(record.versionSeq, tombstone.versionSeq)) return
      await idb.deleteTombstone(record.recordKey)
    }
    const existing = await idb.getTier1(record.projectId, record.recordId)
    // ENC-TSK-Q34 (ENC-ISS-731): domain-safe accept gate (no string compare
    // across integer seq and ISO tokens).
    if (existing && !shouldAcceptRecord(existing, record)) return
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

  async markTombstone(
    recordKey: string,
    recordId: string,
    options: { versionSeq?: string; projectId?: string } = {},
  ): Promise<void> {
    await idb.putTombstone({ recordKey, deletedAt: Date.now(), versionSeq: options.versionSeq })
    // ENC-TSK-Q34: also drop the cached row, or loadSearchSlice would put a
    // deleted/archived record back into the index on the next page load.
    if (options.projectId) await idb.deleteTier1(options.projectId, recordId)
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

  /** ENC-TSK-Q34: drop the counter-sentinel phantom an older corpus left in
   *  IndexedDB, so /docs counts equal the real document count. */
  private async withoutCounterSentinel(rows: Tier1Record[]): Promise<Tier1Record[]> {
    const kept: Tier1Record[] = []
    for (const row of rows) {
      if (row.recordId === DOCUMENT_COUNTER_SENTINEL_ID) {
        await idb.deleteTier1(row.projectId, row.recordId)
        continue
      }
      kept.push(row)
    }
    return kept
  }

  async finalizeWarm(): Promise<void> {
    const rows = await this.withoutCounterSentinel(await idb.listTier1(this.budget.tier1Max))
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
    const rows = await this.withoutCounterSentinel(await idb.listTier1(this.budget.tier1Max))
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
