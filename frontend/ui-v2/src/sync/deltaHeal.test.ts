import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchFeedCorpusPage, fetchFeedDelta } from '../api/client'
import { CacheEngine, getCacheEngine, resetCacheEngineForTests } from './cacheEngine'
import { seedCacheFromCorpus } from './corpusSeed'
import { healCacheFromDelta } from './deltaHeal'
import { getFeedCursors } from './feedVersionMeta'
import type { FeedCorpusItem, FeedDeltaPage } from './types'

/**
 * ENC-TSK-Q34 (AC-1/AC-2/AC-3): delta heal on two cursors. Before Q34 corpus
 * items carried no version_seq, so every load healed from since=0, and
 * documents never travelled through delta at all (ENC-ISS-765).
 */
vi.mock('../api/client', () => ({
  fetchFeedCorpusPage: vi.fn(),
  fetchFeedDelta: vi.fn(),
}))

function page(overrides: Partial<FeedDeltaPage>): FeedDeltaPage {
  return { success: true, since: 0, latest_version_seq: 0, items: [], tombstones: [], ...overrides }
}

function item(recordId: string, source: 'tracker' | 'document', version_seq: number): FeedCorpusItem {
  return {
    record_id: recordId,
    record_type: source === 'document' ? 'document' : 'task',
    project_id: source === 'document' ? 'devops' : 'enceladus',
    title: recordId,
    updated_at: '2026-10-08T03:00:00Z',
    source,
    record_key: source === 'document' ? `document::${recordId}` : `tracker:enceladus:${recordId}`,
    version_seq,
  }
}

describe('healCacheFromDelta', () => {
  beforeEach(() => {
    resetCacheEngineForTests()
    vi.mocked(fetchFeedDelta).mockReset()
    vi.mocked(fetchFeedCorpusPage).mockReset()
  })

  it('pages each sequence space on its own cursor until neither window is truncated', async () => {
    vi.mocked(fetchFeedDelta)
      .mockResolvedValueOnce(page({ latest_version_seq: 5103, truncated: true, latest_doc_version_seq: 185, doc_truncated: false, items: [item('ENC-TSK-1', 'tracker', 5103)] }))
      .mockResolvedValueOnce(page({ latest_version_seq: 5104, truncated: false, latest_doc_version_seq: 185, doc_truncated: false, items: [item('ENC-TSK-2', 'tracker', 5104)] }))

    const cursors = await healCacheFromDelta(new CacheEngine(), { tracker: 5100, document: 185 })

    expect(vi.mocked(fetchFeedDelta).mock.calls.map(([c]) => c)).toEqual([
      { since: 5100, docSince: 185 },
      { since: 5103, docSince: 185 },
    ])
    expect(cursors).toEqual({ tracker: 5104, document: 185 })
    expect(await getFeedCursors()).toEqual({ tracker: 5104, document: 185 })
  })

  it('applies document tombstones with their version and project', async () => {
    const engine = new CacheEngine()
    await engine.ingestCorpusPage([item('DOC-GONE', 'document', 185)])
    vi.mocked(fetchFeedDelta).mockResolvedValueOnce(
      page({
        latest_version_seq: 10,
        truncated: false,
        latest_doc_version_seq: 186,
        doc_truncated: false,
        tombstones: [{ record_key: 'document::DOC-GONE', record_id: 'DOC-GONE', record_type: 'document', project_id: 'devops', version_seq: 186 }],
      }),
    )
    await healCacheFromDelta(engine, { tracker: 10, document: 185 })
    await engine.loadSearchSlice()
    expect(engine.searchIndex.all().map((r) => r.recordId)).not.toContain('DOC-GONE')
  })

  it('keeps paging a pre-Q34 server (no window flags) while it advances', async () => {
    vi.mocked(fetchFeedDelta)
      .mockResolvedValueOnce(page({ latest_version_seq: 3, items: [item('ENC-TSK-3', 'tracker', 3)] }))
      .mockResolvedValueOnce(page({ latest_version_seq: 3 }))
    const cursors = await healCacheFromDelta(new CacheEngine(), { tracker: 0, document: 0 })
    expect(fetchFeedDelta).toHaveBeenCalledTimes(2)
    expect(cursors.tracker).toBe(3)
  })
})

describe('seedCacheFromCorpus cursor seeding (ENC-TSK-Q34 AC-2)', () => {
  beforeEach(() => {
    resetCacheEngineForTests()
    vi.mocked(fetchFeedDelta).mockReset()
    vi.mocked(fetchFeedCorpusPage).mockReset()
  })

  it('heals from the corpus max per space, and the next heal resumes from the stored non-zero cursors', async () => {
    vi.mocked(fetchFeedCorpusPage).mockResolvedValueOnce({
      success: true,
      items: [item('ENC-TSK-1', 'tracker', 5101), item('DOC-2F56AACDD5C0', 'document', 185), item('ENC-TSK-0', 'tracker', 4000)],
      next_cursor: null,
      facets: {},
      total_matches: 3,
    })
    vi.mocked(fetchFeedDelta).mockResolvedValue(
      page({ latest_version_seq: 5101, truncated: false, latest_doc_version_seq: 185, doc_truncated: false }),
    )

    await seedCacheFromCorpus()
    expect(vi.mocked(fetchFeedDelta).mock.calls[0]![0]).toEqual({ since: 5101, docSince: 185 })

    vi.mocked(fetchFeedDelta).mockClear()
    await healCacheFromDelta(getCacheEngine())
    expect(vi.mocked(fetchFeedDelta).mock.calls[0]![0]).toEqual({ since: 5101, docSince: 185 })
  })
})
