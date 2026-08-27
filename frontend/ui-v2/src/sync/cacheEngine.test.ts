import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  CacheEngine,
  corpusItemToTier1,
  resetCacheEngineForTests,
  tier1FromFeedEvent,
} from './cacheEngine'
import type { FeedCorpusItem } from './types'

describe('corpusItemToTier1', () => {
  it('maps corpus items to tier1 rows', () => {
    const item: FeedCorpusItem = {
      record_id: 'ENC-TSK-99',
      record_type: 'task',
      project_id: 'enceladus',
      title: 'Ship cache',
      updated_at: '2026-07-05T12:00:00Z',
      source: 'tracker',
      record_key: 'tracker:enceladus:ENC-TSK-99',
      attrs: { status: 'open', priority: 'high' },
    }
    const row = corpusItemToTier1(item)
    expect(row).toMatchObject({
      recordId: 'ENC-TSK-99',
      recordType: 'task',
      status: 'open',
      priority: 'high',
      versionSeq: '2026-07-05T12:00:00Z',
    })
  })

  it('returns null for unsupported record types', () => {
    expect(
      corpusItemToTier1({
        record_id: 'X',
        record_type: 'unknown',
        project_id: 'enceladus',
        title: 'X',
        source: 'tracker',
        record_key: 'k',
      }),
    ).toBeNull()
  })
})

describe('CacheEngine', () => {
  beforeEach(() => {
    resetCacheEngineForTests()
  })

  it('ingests corpus pages and warms the search index', async () => {
    const engine = new CacheEngine({ tier1Max: 100, tier2Max: 10, searchIndexMax: 100 })
    const count = await engine.ingestCorpusPage([
      {
        record_id: 'ENC-TSK-1',
        record_type: 'task',
        project_id: 'enceladus',
        title: 'One',
        source: 'tracker',
        record_key: 'tracker:enceladus:ENC-TSK-1',
      },
      {
        record_id: 'DOC-1',
        record_type: 'document',
        project_id: 'global',
        title: 'Doc',
        source: 'document',
        record_key: 'document::DOC-1',
      },
    ])
    await engine.finalizeWarm()

    expect(count).toBe(2)
    expect(engine.searchIndex.all()).toHaveLength(2)
    expect(engine.isWarm).toBe(true)
  })

  it('rejects stale tier2 writes and evicts LRU rows', async () => {
    vi.useFakeTimers()
    const engine = new CacheEngine({ tier1Max: 10, tier2Max: 2, searchIndexMax: 10 })

    vi.setSystemTime(1_000)
    await engine.upsertTier2('enceladus', 'A', { id: 'A' }, '2')
    vi.setSystemTime(2_000)
    await engine.upsertTier2('enceladus', 'B', { id: 'B' }, '2')
    vi.setSystemTime(3_000)
    await engine.getTier2Body('enceladus', 'A')
    vi.setSystemTime(4_000)
    await engine.upsertTier2('enceladus', 'C', { id: 'C' }, '2')

    expect(await engine.getTier2Body('enceladus', 'B')).toBeNull()
    expect(await engine.getTier2Body('enceladus', 'A')).toEqual({ id: 'A' })
    expect(await engine.getTier2Body('enceladus', 'C')).toEqual({ id: 'C' })

    vi.setSystemTime(5_000)
    await engine.upsertTier2('enceladus', 'A', { id: 'A-old' }, '1')
    expect(await engine.getTier2Body('enceladus', 'A')).toEqual({ id: 'A' })
    vi.useRealTimers()
  })

  it('marks tombstones and removes search rows', async () => {
    const engine = new CacheEngine()
    const tier1 = tier1FromFeedEvent({
      recordId: 'ENC-TSK-9',
      recordType: 'task',
      projectId: 'enceladus',
      title: 'Gone',
    })
    expect(tier1).not.toBeNull()
    await engine.upsertTier1(tier1!)
    await engine.markTombstone(tier1!.recordKey, tier1!.recordId)

    expect(engine.searchIndex.all()).toHaveLength(0)
    await engine.upsertTier1(tier1!)
    expect(engine.searchIndex.all()).toHaveLength(0)
  })
})

// ENC-ISS-711: the search index must be populated by recency, so a corpus
// larger than the index budget keeps the most-recently-updated records rather
// than whatever happens to sort first in IndexedDB primary-key order. Before
// this fix, `finalizeWarm` sliced `listTier1(...)` in key order, filling the cap
// with alphabetically-early projects/documents and dropping the recent
// `enceladus:ENC-*` band entirely.
describe('CacheEngine finalizeWarm recency selection (ENC-ISS-711)', () => {
  beforeEach(() => {
    resetCacheEngineForTests()
  })

  const item = (
    project: string,
    id: string,
    type: 'task' | 'issue',
    updated: string,
  ): FeedCorpusItem => ({
    record_id: id,
    record_type: type,
    project_id: project,
    title: id,
    updated_at: updated,
    source: 'tracker',
    record_key: `tracker:${project}:${id}`,
  })

  it('keeps the most-recently-updated records when the corpus exceeds searchIndexMax', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const engine = new CacheEngine({ tier1Max: 100, tier2Max: 10, searchIndexMax: 3 })
    // Insert OLD other-project rows first, then the RECENT cutover-week ENC band
    // last -- mirroring the prod ordering where ENC-* records sort after other
    // projects and enceladus documents. A key-order/insertion-order slice would
    // keep the four old rows and drop the ENC band; recency selection must not.
    await engine.ingestCorpusPage([
      item('devops', 'DVP-TSK-100', 'task', '2020-01-01T00:00:00Z'),
      item('devops', 'DVP-TSK-101', 'task', '2020-02-01T00:00:00Z'),
      item('chosen-family', 'CFY-TSK-1', 'task', '2019-06-01T00:00:00Z'),
      item('enceladus', 'DOC-STALE', 'issue', '2018-01-01T00:00:00Z'),
      item('enceladus', 'ENC-TSK-P56', 'task', '2026-08-27T02:00:00Z'),
      item('enceladus', 'ENC-TSK-P60', 'task', '2026-08-27T04:00:00Z'),
      item('enceladus', 'ENC-ISS-711', 'issue', '2026-08-27T04:30:00Z'),
    ])
    await engine.finalizeWarm()

    const ids = engine.searchIndex.all().map((r) => r.recordId)
    expect(ids).toHaveLength(3)
    expect(new Set(ids)).toEqual(new Set(['ENC-ISS-711', 'ENC-TSK-P60', 'ENC-TSK-P56']))
    // No silent cap: truncation must be surfaced.
    expect(warn).toHaveBeenCalledOnce()
    warn.mockRestore()
  })

  it('holds the full corpus (no truncation, no warn) when it fits the budget', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const engine = new CacheEngine({ tier1Max: 100, tier2Max: 10, searchIndexMax: 100 })
    await engine.ingestCorpusPage([
      item('devops', 'DVP-TSK-100', 'task', '2020-01-01T00:00:00Z'),
      item('enceladus', 'ENC-TSK-P56', 'task', '2026-08-27T02:00:00Z'),
      item('enceladus', 'ENC-ISS-711', 'issue', '2026-08-27T04:30:00Z'),
    ])
    await engine.finalizeWarm()

    const ids = engine.searchIndex.all().map((r) => r.recordId)
    expect(new Set(ids)).toEqual(new Set(['DVP-TSK-100', 'ENC-TSK-P56', 'ENC-ISS-711']))
    expect(warn).not.toHaveBeenCalled()
    warn.mockRestore()
  })

  it('loadSearchSlice reads the full tier1 set and orders it by recency', async () => {
    const engine = new CacheEngine({ tier1Max: 100, tier2Max: 10, searchIndexMax: 2 })
    await engine.ingestCorpusPage([
      item('devops', 'DVP-TSK-1', 'task', '2020-01-01T00:00:00Z'),
      item('devops', 'DVP-TSK-2', 'task', '2020-02-01T00:00:00Z'),
      item('enceladus', 'ENC-TSK-P60', 'task', '2026-08-27T04:00:00Z'),
    ])
    await engine.loadSearchSlice()

    const ids = engine.searchIndex.all().map((r) => r.recordId)
    expect(ids).toHaveLength(2)
    expect(ids).toContain('ENC-TSK-P60')
    expect(ids).not.toContain('DVP-TSK-1')
  })
})
