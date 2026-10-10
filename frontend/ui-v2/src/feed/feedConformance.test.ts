/**
 * DVP-TSK-919 AC1/AC2: the @io-kit/feed conformance suite (FT-01..FT-12) replayed against the fixture that
 * backend/lambda/feed_query/test_conformance_fixture.py generates from feed_query's own handler code
 * (signed v1 cursors, single-colon record_key, real 400 body). CI runs both halves; the pytest half fails if the
 * committed fixture is stale, so this runner always sees what the handler emits.
 * FT-13 (Playwright WebKit render smoke) is skipped: ui-v2 has no Playwright setup yet.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { createReplayFetch, runFixtureConformance, type ReplayFixture } from '@io-kit/feed/testing'
import { CursorInvalidError } from '@io-kit/feed'
import { createEnceladusFeedSource, type FeedCorpusRecord } from './enceladusFeedSource'

const path = join(dirname(fileURLToPath(import.meta.url)), '../../../../backend/lambda/feed_query/conformance/enceladus-feed-query.json')
const fx = JSON.parse(readFileSync(path, 'utf8')) as ReplayFixture & {
  head_seq: number
  invalid_cursor: { sort: string; cursor: string }
}

function target() {
  const replay = createReplayFetch(fx)
  const source = createEnceladusFeedSource({ fetch: replay.fetch, apiBase: '/api/v1', now: () => Date.parse(fx.now) })
  return { replay, source }
}

describe('feed_query handler output vs @io-kit/feed conformance (FT-01..FT-12)', () => {
  it('passes every applicable case; nothing fails and cursor signing is exercised, not skipped', async () => {
    const { replay, source } = target()
    const report = await runFixtureConformance<FeedCorpusRecord, { sort: string }>({
      name: 'enceladus-feed-query',
      source,
      replay,
      filter: { sort: 'updated_at_desc' },
      pageSize: fx.page_size,
      expectedIds: fx.expected_head_ids,
      sortKey: (i) => i.updated_at ?? '',
      invalidCursor: { filter: { sort: 'updated_at_desc' }, cursor: fx.invalid_cursor.cursor },
      delta: { seq: 115, upserts: ['ENC-TSK-1116', 'ENC-TSK-1117', 'ENC-TSK-1118', 'ENC-TSK-1119', 'ENC-TSK-1120', 'ENC-TSK-1110'], deletes: ['ENC-TSK-1100'], head: 122 },
      gap: { seq: 0 },
      afterEdit: { signalSeq: 122, headId: 'ENC-TSK-1110', removedId: 'ENC-TSK-1100' },
    })
    const failed = report.results.filter((r) => r.status === 'fail')
    expect(failed, JSON.stringify(failed)).toEqual([])
    expect(report.ok).toBe(true)
    const byId = new Map(report.results.map((r) => [r.id, r.status]))
    expect(byId.get('FT-03-cursor-signing')).toBe('pass')
    expect(report.results.filter((r) => r.status === 'pass').length).toBeGreaterThanOrEqual(8)
  })

  it('fixture carries signed v1 cursors and the real single-colon record_key', () => {
    const pages = fx.recorded.filter((r) => r.request.path.endsWith('/corpus') && r.status === 200)
    for (const p of pages) {
      const next = (p.response as { next_cursor: string | null }).next_cursor
      if (next) expect(next).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
    }
    const key = ((pages[0]!.response as { items: FeedCorpusRecord[] }).items[0]!).record_key
    expect(key).toBe('tracker:enceladus:ENC-TSK-1120')
  })

  it('a 400 on a cursor request is a cursor reset; delta ops are in seq order; truncated is gap_too_large', async () => {
    const { replay, source } = target()
    const sig = new AbortController().signal
    await expect(
      source.page({ filter: { sort: 'updated_at_desc' }, cursor: fx.invalid_cursor.cursor as never, limit: 50, signal: sig }),
    ).rejects.toBeInstanceOf(CursorInvalidError)
    replay.setPhase('after_edit')
    const d = await source.since({ filter: {}, seq: 115, signal: sig })
    expect(d.ops.map((o) => o.seq)).toEqual([...d.ops.map((o) => o.seq)].sort((a, b) => a - b))
    expect(d.ops.some((o) => o.op === 'delete' && o.id === 'ENC-TSK-1100')).toBe(true)
    expect(d.head_seq).toBe(122)
    expect((await source.since({ filter: {}, seq: 0, signal: sig })).gap_too_large).toBe(true)
  })
})
