/**
 * DVP-TSK-921 AC1: the enceladus SearchSource passes the @io-kit/search conformance runner.
 * CI replays the live-recorded graphsearch responses (E3-R22: graphsearch needs auth); with
 * GRAPHSEARCH_COOKIE set (and optionally GRAPHSEARCH_BASE_URL) the same runner takes a live fetch.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it, vi } from 'vitest'
import { mergeTiers, type SearchRequest } from '@io-kit/search'
import { assertSearchSourceConformance } from '@io-kit/search/testing'
import { createHostSearchSource } from './enceladusSearchSource'
import { kitHitsToResultHits, localToResult } from './kitHits'
import { feedSearchToParams, parseFeedSearch } from './feedSearchParams'
import { createUrlCodec } from '@io-kit/search'

const dir = join(dirname(fileURLToPath(import.meta.url)), '__fixtures__')
const fixture = (n: string) => JSON.parse(readFileSync(join(dir, `enc-graphsearch-${n}.json`), 'utf8')) as unknown

function recordedFetch() {
  const urls: string[] = []
  const fetcher = async (url: string) => {
    urls.push(url)
    const which = new URL(url, 'https://x.invalid').searchParams.get('project_id') === 'devops' ? 'devops' : 'hybrid'
    const body = fixture(which)
    return { ok: true, status: 200, json: async () => body }
  }
  return { fetcher, urls }
}

function liveFetch(cookie: string, base: string) {
  return async (url: string, init: { signal?: AbortSignal }) => {
    // eslint-disable-next-line no-restricted-globals -- opt-in live run (GRAPHSEARCH_COOKIE), not app code
    const res = await fetch(`${base}${url}`, { signal: init.signal, headers: { cookie, accept: 'application/json' } })
    return { ok: res.ok, status: res.status, json: () => res.json() as Promise<unknown> }
  }
}

const noRelate = async () => undefined
const live = process.env.GRAPHSEARCH_COOKIE
const requests: SearchRequest[] = [
  { q: 'feed', limit: 10, filters: { project_id: 'enceladus' } },
  { q: 'search', signals: ['keyword', 'vector'], filters: { project_id: 'devops' } },
]

describe.skipIf(Boolean(live))('recorded graphsearch responses', () => {
  it('pass the kit conformance runner (graph marked unavailable, never dropped)', async () => {
    const { fetcher, urls } = recordedFetch()
    const source = createHostSearchSource({ fetch: fetcher, relate: noRelate })
    const report = await assertSearchSourceConformance(source, { requests, expectUnavailable: ['graph'] })
    expect(report.passed).toBe(true)
    expect(urls[0]).toContain('/api/v1/tracker/graphsearch?')
    expect(urls[0]).toContain('search_type=hybrid')
    expect(urls[0]).toContain('project_id=enceladus')
  })
})

describe.runIf(Boolean(live))('live graphsearch', () => {
  it('passes the kit conformance runner against the endpoint', async () => {
    const source = createHostSearchSource({
      fetch: liveFetch(live as string, process.env.GRAPHSEARCH_BASE_URL ?? 'https://jreese.net') as never,
      relate: noRelate, // the runner exercises relate: never write a real edge from a conformance run
    })
    const report = await assertSearchSourceConformance(source, { requests, expectUnavailable: ['graph'] })
    expect(report.passed).toBe(true)
  }, 60_000)
})

describe('two-tier merge, evidence and degraded display model', () => {
  it('hybrid order wins, tiers are tagged, per-signal evidence keeps nulls, graph is degraded', async () => {
    const { fetcher } = recordedFetch()
    const source = createHostSearchSource({ fetch: fetcher })
    const res = await source.query({ q: 'feed', filters: { project_id: 'enceladus' } })
    expect(res.signal_availability.graph).toBe('unavailable')
    expect(res.degraded.map((d) => d.signal)).toContain('graph')
    expect(res.partial).toBe(true)
    const top = res.results[0]!
    const local = [{ recordId: 'ENC-TSK-LOCALONLY', recordType: 'task' as const, projectId: 'enceladus', title: 'feed local only', status: 'open' }]
    const merged = mergeTiers(
      [localToResult({ ...local[0]!, tier: 'local' }, 0), localToResult({ recordId: top.id, recordType: 'task', projectId: 'enceladus', title: top.title, tier: 'local' }, 1)],
      res.results,
    )
    const hits = kitHitsToResultHits(merged, 'enceladus', local)
    expect(hits[0]!.recordId).toBe(top.id)
    expect(hits[0]!.tier).toBe('hybrid')
    expect(hits.filter((h) => h.recordId === top.id)).toHaveLength(1)
    expect(hits.at(-1)!.recordId).toBe('ENC-TSK-LOCALONLY')
    expect(hits.at(-1)!.tier).toBe('local')
    const ev = merged[0]!.evidence
    expect(ev.find((e) => e.signal === 'graph')!.rank).toBeNull()
    expect(ev.every((e) => e.rank !== 0)).toBe(true)
  })

  it('onPin goes through relate -> tracker.relate with from/to', async () => {
    const relate = vi.fn(async () => undefined)
    const source = createHostSearchSource({ fetch: recordedFetch().fetcher, relate })
    const edge = await source.relate!({ from: 'ENC-TSK-1', to: 'ENC-TSK-2', rel: 'related', created_by: 'human' })
    expect(relate).toHaveBeenCalledWith('ENC-TSK-1', 'ENC-TSK-2')
    expect(edge).toEqual({ from: 'ENC-TSK-1', to: 'ENC-TSK-2', rel: 'related', created_by: 'human' })
  })
})

describe('existing search URLs round-trip (AC3)', () => {
  // The Feed keeps writing URLs through feedSearchParams (unchanged tests). The kit codec must READ every existing
  // link: q and the property filter decode, unmapped keys (op/sort/scroll) are preserved in extras, and decoding is stable.
  const codec = createUrlCodec('enceladus')
  for (const raw of [
    { q: 'feed engine', f: 'status|=|open;priority|=|P1', op: 'and', sort: 'updated', scroll: 240 },
    { q: '', f: '', op: 'or', sort: 'tier', scroll: 0 },
    { q: 'ENC-TSK-1', f: 'record_type|=|task', op: 'and', sort: 'id', scroll: 0 },
  ]) {
    it(`?${JSON.stringify(raw)}`, () => {
      const search = parseFeedSearch(raw)
      const params = feedSearchToParams(search)
      expect(parseFeedSearch(Object.fromEntries(params))).toEqual(search) // the app's own round trip is exact
      const state = codec.decode(params)
      expect(state.query.q).toBe(raw.q)
      expect(JSON.stringify(state.query.filters ?? {})).toBe(JSON.stringify(codec.decode(codec.encode(state)).query.filters ?? {}))
    })
  }
})
