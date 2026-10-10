/**
 * enceladusFeedSource.ts -- DVP-TSK-919 (DVP-PLN-011 E3-W2.6): @io-kit/feed FeedSource over feed_query.
 *
 *   page  -> GET /feed/corpus?limit&sort&cursor   (keyset, signed v1 cursors minted by feed_query)
 *   since -> GET /feed/delta?since=<version_seq>  (ops in seq order; `truncated` == gap_too_large)
 *
 * Cursors are opaque here: the server signs and verifies them. A 400 on a request that carried a cursor is
 * a cursor reset (CursorInvalidError), so the engine refetches the head instead of surfacing an error.
 * Realtime stays signal-then-fetch over the existing AppSync channel, bridged in by `subscribe`.
 */
import { CursorInvalidError, type Cursor, type DeltaResponse, type FeedSource, type PageResponse, type Seq } from '@io-kit/feed'
import { API_BASE } from '../api/client'
import { browserFetch } from '../api/feedFetch'

export interface FeedCorpusRecord {
  record_id: string
  record_key: string
  record_type: string
  project_id?: string
  title?: string
  updated_at?: string
  version_seq?: number
  [k: string]: unknown
}

export interface EnceladusFeedFilter {
  sort?: string
  q?: string
}

import type { FetchLike } from '../api/feedFetch'
export type { FetchLike }

interface CorpusBody {
  items?: FeedCorpusRecord[]
  next_cursor?: string | null
}
interface DeltaBody {
  latest_version_seq: number
  truncated?: boolean
  items?: FeedCorpusRecord[]
  tombstones?: Array<{ record_id: string; version_seq: number }>
}

function qs(q: Record<string, string | undefined>): string {
  return new URLSearchParams(Object.entries(q).filter((e): e is [string, string] => e[1] !== undefined)).toString()
}

export function createEnceladusFeedSource(
  o: {
    fetch?: FetchLike
    apiBase?: string
    now?: () => number
    subscribe?: FeedSource<FeedCorpusRecord, EnceladusFeedFilter>['subscribe']
  } = {},
): FeedSource<FeedCorpusRecord, EnceladusFeedFilter> {
  const doFetch = o.fetch ?? browserFetch
  const base = o.apiBase ?? API_BASE
  const now = o.now ?? (() => Date.now())

  async function getJson<B>(path: string, signal: AbortSignal): Promise<{ status: number; body: B }> {
    const res = await doFetch(`${base}${path}`, { signal })
    let body: unknown = {}
    try {
      body = await res.json()
    } catch {
      /* non-JSON error body */
    }
    return { status: res.status, body: body as B }
  }

  return {
    key: (f) => ['enceladus-feed', f?.sort ?? 'updated_at_desc', f?.q ?? ''],
    getId: (r) => r.record_id,
    async page({ filter, cursor, limit, direction, signal }): Promise<PageResponse<FeedCorpusRecord>> {
      if (direction === 'newer') throw new Error('feed_query has no newer-direction page')
      const { status, body } = await getJson<CorpusBody & { error_envelope?: { code?: string } }>(
        `/feed/corpus?${qs({ limit: String(limit), sort: filter?.sort ?? 'updated_at_desc', q: filter?.q || undefined, cursor: cursor ?? undefined })}`,
        signal,
      )
      if (status === 400 && cursor) throw new CursorInvalidError(String(body.error_envelope?.code ?? 'cursor_invalid'))
      if (status >= 400) throw Object.assign(new Error(`feed corpus ${status}`), { status })
      const items = body.items ?? []
      const next = (body.next_cursor ?? null) as Cursor | null
      const page: PageResponse<FeedCorpusRecord> = {
        items,
        next_cursor: next,
        has_more: next !== null,
        server_time: new Date(now()).toISOString(),
        schema: 'feed.v1',
      }
      const seqs = items.map((i) => i.version_seq).filter((s): s is number => typeof s === 'number')
      if (cursor === null && seqs.length > 0) page.head_seq = Math.max(...seqs)
      return page
    },
    async since({ seq, signal }): Promise<DeltaResponse<FeedCorpusRecord>> {
      const { status, body } = await getJson<DeltaBody>(`/feed/delta?${qs({ since: String(seq) })}`, signal)
      if (status >= 400) throw Object.assign(new Error(`feed delta ${status}`), { status })
      const head: Seq = body.latest_version_seq
      // A truncated delta (more than MAX_DELTA_ITEMS rows behind) is the gap: drop the buffer, refetch the head.
      if (body.truncated === true) return { ops: [], head_seq: head, gap_too_large: true }
      const ops = [
        ...(body.items ?? []).map((item) => ({ op: 'upsert' as const, id: item.record_id, seq: item.version_seq ?? head, item })),
        ...(body.tombstones ?? []).map((t) => ({ op: 'delete' as const, id: t.record_id, seq: t.version_seq })),
      ].sort((a, b) => a.seq - b.seq)
      return { ops, head_seq: head }
    },
    subscribe: o.subscribe,
  }
}

/** Bridges the app's existing AppSync provider into the kit's subscribe(): the panel calls emit()/status(). */
export function createSignalBridge() {
  let onSignal: ((s: { feed: string }) => void) | null = null
  let onStatus: ((s: 'connecting' | 'live' | 'stale' | 'reconnecting' | 'offline' | 'snapshot') => void) | null = null
  let last: 'connecting' | 'live' | 'stale' | 'reconnecting' | 'offline' | 'snapshot' = 'snapshot'
  return {
    subscribe: (a: { onSignal(s: { feed: string }): void; onStatus(s: typeof last): void }) => {
      onSignal = a.onSignal
      onStatus = a.onStatus
      a.onStatus(last)
      return () => {
        onSignal = null
        onStatus = null
      }
    },
    emit: () => onSignal?.({ feed: 'enceladus' }),
    status: (s: typeof last) => {
      last = s
      onStatus?.(s)
    },
  }
}
