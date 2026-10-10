/**
 * enceladusSearchSource.ts -- DVP-TSK-921 (DVP-PLN-011 E3-W3.1): the enceladus SearchSource for @io-kit/search.
 *
 * The kit's createEnceladusSource maps GET /api/v1/tracker/graphsearch?search_type=hybrid (signal_availability,
 * _per_signal_ranks, _final_rank) onto the SearchResponse contract, including the degraded rules (graph is
 * `unavailable` on enceladus today, so responses are partial with graph degraded). This module supplies the host
 * pieces: a same-origin cookie fetch, a side map of the raw node fields the contract does not carry (status,
 * priority, project, updated_at) for the result cards, and `relate` wired to tracker.relate (pin).
 */
import { createEnceladusSource, type RelateRequest, type SearchSource } from '@io-kit/search'
import { browserSearchFetch } from '../api/searchFetch'
import { relateRecords } from '../api/actions'

export interface RawGraphNode {
  record_id: string
  project_id?: string
  status?: string
  priority?: string
  updated_at?: string
  title?: string
  _labels?: string[]
}

const RAW_CAP = 500
const rawNodes = new Map<string, RawGraphNode>()
export const rawNodeFor = (id: string): RawGraphNode | undefined => rawNodes.get(id)

type Fetcher = Parameters<typeof createEnceladusSource>[0]['fetch']

/** Wraps a fetch so graphsearch node fields are retained beside the normalized response. */
export function withNodeCapture(inner: Fetcher): Fetcher {
  return async (url, init) => {
    const res = await inner(url, init)
    return {
      ok: res.ok,
      status: res.status,
      json: async () => {
        const body = await res.json()
        const nodes = (body as { nodes?: RawGraphNode[] } | null)?.nodes
        if (Array.isArray(nodes)) {
          if (rawNodes.size > RAW_CAP) rawNodes.clear()
          for (const n of nodes) if (n?.record_id) rawNodes.set(n.record_id, n)
        }
        return body
      },
    }
  }
}

export function createHostSearchSource(opts: { fetch?: Fetcher; relate?: (from: string, to: string) => Promise<void> } = {}): SearchSource {
  const base = createEnceladusSource({ baseUrl: '', fetch: withNodeCapture(opts.fetch ?? browserSearchFetch) })
  const relate = opts.relate ?? ((from: string, to: string) => relateRecords(from, to))
  return {
    ...base,
    async relate(req: RelateRequest) {
      await relate(req.from, req.to)
      return req
    },
  }
}

export const hostSearchSource: SearchSource = createHostSearchSource()
