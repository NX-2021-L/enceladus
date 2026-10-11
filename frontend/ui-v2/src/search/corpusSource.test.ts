import { describe, expect, it } from 'vitest'
import { CorpusStore, createMemoryCorpusStorage } from '@io-kit/search/corpus'
import {
  createEnceladusCorpusSource,
  liveChangeFromEvent,
  mapCorpusItem,
  suggestRows,
  type CorpusFetchers,
} from './corpusSource'
import type { FeedCorpusItem, FeedCorpusPage, FeedDeltaPage } from '../sync/types'
import type { FeedRealtimeEvent } from '../types/feedEvents'

const item = (over: Partial<FeedCorpusItem> & { record_id: string }): FeedCorpusItem => ({
  record_type: 'task',
  project_id: 'enceladus',
  title: `title ${over.record_id}`,
  updated_at: '2026-10-01T00:00:00Z',
  source: 'tracker',
  record_key: `tracker:enceladus:${over.record_id}`,
  version_seq: 1,
  attrs: {},
  ...over,
})
const doc = (id: string, seq: number): FeedCorpusItem =>
  item({ record_id: id, record_type: 'document', project_id: 'devops', source: 'document', record_key: `document::${id}`, version_seq: seq })

const page = (items: FeedCorpusItem[], next: string | null): FeedCorpusPage => ({ success: true, items, next_cursor: next, facets: {}, total_matches: 0 })

describe('mapCorpusItem', () => {
  it('maps the design-section-4 fields', () => {
    const row = mapCorpusItem(
      item({
        record_id: 'ENC-TSK-1',
        attrs: { status: 'open', priority: 'P1', category: 'implementation', checkout_state: 'checked_out', components: ['a', 'b'], tags: ['x'], created_at: '2026-09-01T00:00:00Z' },
      }),
    )!
    expect(row.key).toBe('tracker:enceladus:ENC-TSK-1')
    expect(row.type).toBe('task')
    expect(row.fields).toMatchObject({
      id: 'ENC-TSK-1', record_type: 'task', project_id: 'enceladus', status: 'open', priority: 'P1', category: 'implementation',
      checkout_state: 'checked_out', components: ['a', 'b'], tags: ['x'], created_at: '2026-09-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
    })
    expect(row.version).toBe('1')
  })
  it('drops the document counter sentinel and unknown types', () => {
    expect(mapCorpusItem(item({ record_id: '__COUNTER__VERSION_SEQ__', record_type: 'document' }))).toBeNull()
    expect(mapCorpusItem(item({ record_id: 'X-1', record_type: 'session' }))).toBeNull()
  })
})

describe('CorpusSource: two sequence spaces', () => {
  const pages: Record<string, FeedCorpusPage> = {
    '': page([item({ record_id: 'ENC-TSK-1', version_seq: 5101 }), doc('DOC-A', 185)], 'c2'),
    c2: page([item({ record_id: 'ENC-TSK-2', version_seq: 5099 })], null),
  }
  const deltaCalls: Array<{ since: number; docSince: number }> = []
  const fetchers: CorpusFetchers = {
    corpus: async ({ cursor }) => pages[cursor ?? '']!,
    delta: async (cursors) => {
      deltaCalls.push(cursors)
      const out: FeedDeltaPage = {
        success: true,
        since: cursors.since,
        latest_version_seq: 5110,
        latest_doc_version_seq: 190,
        items: [item({ record_id: 'ENC-TSK-1', version_seq: 5110, title: 'renamed' })],
        tombstones: [{ record_key: 'document::DOC-A', record_id: 'DOC-A', record_type: 'document', project_id: 'devops', version_seq: 190 }],
        truncated: false,
        doc_truncated: true,
      }
      return out
    },
  }
  const source = createEnceladusCorpusSource(fetchers)

  it('declares both spaces and seeds with per-space cursors, never max()-merged', async () => {
    expect(source.seqSpaces).toEqual(['tracker', 'document'])
    const seen: Array<Record<string, unknown>> = []
    let rows = 0
    for await (const p of source.seed({})) {
      rows += p.rows.length
      seen.push(p.cursors ?? {})
    }
    expect(rows).toBe(3)
    expect(seen.at(-1)).toEqual({ tracker: 5101, document: 185 })
  })

  it('since() sends both cursors, maps tombstones with their version and reports a truncated window per either space', async () => {
    const d = await source.since({ tracker: 5101, document: 185 }, {})
    expect(deltaCalls.at(-1)).toEqual({ since: 5101, docSince: 185 })
    expect(d.cursors).toEqual({ tracker: 5110, document: 190 })
    expect(d.deletes).toEqual([{ key: 'document::DOC-A', version: '190' }])
    expect(d.truncated).toBe(true)
  })

  it('tombstones win until a strictly newer version of the same record arrives', async () => {
    const store = new CorpusStore(createMemoryCorpusStorage(), { budget: 100, seqSpaces: ['tracker', 'document'] })
    await store.upsertMany([mapCorpusItem(doc('DOC-A', 185))!])
    await store.remove('document::DOC-A', { version: '190' })
    expect(store.get('document::DOC-A')).toBeUndefined()
    await store.upsertMany([mapCorpusItem(doc('DOC-A', 186))!]) // older than the tombstone: stays deleted
    expect(store.get('document::DOC-A')).toBeUndefined()
    await store.upsertMany([mapCorpusItem(doc('DOC-A', 191))!]) // un-archived by a newer write
    expect(store.get('document::DOC-A')?.title).toBe('title DOC-A')
  })
})

describe('AppSync events -> applyLiveEvent', () => {
  const ev = (over: Partial<FeedRealtimeEvent>): FeedRealtimeEvent => ({
    eventId: 'e1', recordId: 'ENC-TSK-1', record_type: 'task', action: 'updated', actorType: 'agent', actorId: 'a', summary: 'thin summary', cursor: 1, channels: [], ...over,
  })
  const existing = mapCorpusItem(item({ record_id: 'ENC-TSK-1', version_seq: 7, attrs: { status: 'open', priority: 'P1' } }))!

  it('merges onto the stored row instead of stomping governed fields', () => {
    const c = liveChangeFromEvent(ev({ recordStatus: 'closed', recordUpdatedAt: '2026-10-02T00:00:00Z' }), [existing])
    expect(c).toMatchObject({ upsert: { fields: { status: 'closed', priority: 'P1' }, updatedAt: '2026-10-02T00:00:00Z', version: '7', title: existing.title } })
  })
  it('creates a row for an unseen record and tombstones removals with the stored version', () => {
    expect(liveChangeFromEvent(ev({ recordId: 'ENC-TSK-9', recordTitle: 'new' }), [])).toMatchObject({ upsert: { id: 'ENC-TSK-9', key: 'tracker:enceladus:ENC-TSK-9', title: 'new' } })
    expect(liveChangeFromEvent(ev({ action: 'removed' }), [existing])).toEqual({ remove: { key: 'tracker:enceladus:ENC-TSK-1', version: '7' } })
    expect(liveChangeFromEvent(ev({ action: 'removed', recordId: 'ENC-TSK-404' }), [existing])).toBeNull()
  })
})

describe('suggestRows', () => {
  it('ranks id prefixes before title matches', () => {
    const rows = ['ENC-TSK-12', 'ENC-TSK-120'].map((id) => mapCorpusItem(item({ record_id: id }))!).concat(mapCorpusItem(item({ record_id: 'ENC-ISS-1', title: 'mentions ENC-TSK-12 here' }))!)
    expect(suggestRows(rows, 'enc-tsk-12').map((r) => r.id)).toEqual(['ENC-TSK-12', 'ENC-TSK-120', 'ENC-ISS-1'])
    expect(suggestRows(rows, '')).toEqual([])
  })
})
