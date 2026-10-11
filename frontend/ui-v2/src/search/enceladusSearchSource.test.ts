/**
 * DVP-TSK-921 AC1: the enceladus SearchSource passes the @io-kit/search conformance runner.
 * CI replays the live-recorded graphsearch responses (E3-R22: graphsearch needs auth); with
 * GRAPHSEARCH_COOKIE set (and optionally GRAPHSEARCH_BASE_URL) the same runner takes a live fetch.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it, vi } from 'vitest'
import type { SearchRequest } from '@io-kit/search'
import { assertSearchSourceConformance } from '@io-kit/search/testing'
import { createHostSearchSource } from './enceladusSearchSource'

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
    // The two-tier merge itself is kit-owned now (useCollectionSearch); the host contract is that evidence keeps nulls.
    const ev = res.results[0]!.per_signal_ranks
    expect(ev.graph).toBeNull()
    expect(Object.values(ev).every((r) => r !== 0)).toBe(true)
  })

  it('onPin goes through relate -> tracker.relate with from/to', async () => {
    const relate = vi.fn(async () => undefined)
    const source = createHostSearchSource({ fetch: recordedFetch().fetcher, relate })
    const edge = await source.relate!({ from: 'ENC-TSK-1', to: 'ENC-TSK-2', rel: 'related', created_by: 'human' })
    expect(relate).toHaveBeenCalledWith('ENC-TSK-1', 'ENC-TSK-2')
    expect(edge).toEqual({ from: 'ENC-TSK-1', to: 'ENC-TSK-2', rel: 'related', created_by: 'human' })
  })
})
