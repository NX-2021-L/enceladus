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
