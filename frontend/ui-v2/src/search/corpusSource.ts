import {
  CorpusStore,
  createCorpusStorage,
  createLiveApplier,
  type CorpusSource,
  type Cursors,
  type DeltaResult,
  type LiveChange,
  type SeedPage,
} from '@io-kit/search/corpus'
import type { IndexRow } from '@io-kit/search'
import { fetchFeedCorpusPage, fetchFeedDelta } from '../api/client'
import { projectRegistryQueryOptions, resolveProjectFromRecordId } from '../api/projectRegistry'
import { queryClient } from '../api/queryClient'
import type { ProjectSummary } from '../api/projects'
import type { FeedCorpusItem, FeedCorpusPage, FeedDeltaPage } from '../sync/types'
import type { FeedRealtimeEvent } from '../types/feedEvents'

/**
 * DVP-TSK-995 (kit search 1.0, design section 4): the CorpusSource adapter for enceladus.
 *
 *   seed  GET /api/v1/feed/corpus   (limit 200, signed cursor)
 *   since GET /api/v1/feed/delta?since=<tracker seq>&doc_since=<document seq>
 *
 * Two sequence spaces, tracker and document, ride as separate cursors and are never max()-merged across spaces.
 * Same-origin cookie fetch comes from api/client (requestJson). AppSync /feed/updates events merge through
 * applyFeedEventToCorpus.
 */
export const CORPUS_ID = 'enceladus-corpus'
export const SEQ_SPACES = ['tracker', 'document'] as const
export const CORPUS_BUDGET = 20_000
export const SEED_PAGE_LIMIT = 200
const VALID_TYPES = new Set(['task', 'issue', 'feature', 'plan', 'lesson', 'document'])
// document_api's version_seq counter row; never a record (ENC-TSK-Q34).
export const DOCUMENT_COUNTER_SENTINEL_ID = '__COUNTER__VERSION_SEQ__'

export const rowKeyFor = (type: string, projectId: string, id: string): string =>
  type === 'document' ? `document::${id}` : `tracker:${projectId}:${id}`

const str = (v: unknown): string | undefined => (typeof v === 'string' && v ? v : undefined)
const list = (v: unknown): string[] | undefined => {
  const out = Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x !== '') : typeof v === 'string' && v ? [v] : []
  return out.length > 0 ? out : undefined
}

/** feed_query item -> IndexRow (record_type, project_id, status, priority, category, checkout_state, components[], tags[], dates, title, id). */
export function mapCorpusItem(item: FeedCorpusItem): IndexRow | null {
  if (item.record_id === DOCUMENT_COUNTER_SENTINEL_ID) return null
  const type = String(item.record_type ?? '').toLowerCase()
  if (!VALID_TYPES.has(type)) return null
  const attrs = (item.attrs ?? {}) as Record<string, unknown>
  const pick = (k: string): unknown => attrs[k] ?? (item as unknown as Record<string, unknown>)[k]
  const projectId = item.project_id || (type === 'document' ? 'global' : 'enceladus')
  const title = item.title || item.record_id
  const version = item.version_seq != null && Number.isFinite(item.version_seq) ? String(item.version_seq) : item.updated_at?.trim() || '0'
  return {
    id: item.record_id,
    key: item.record_key || rowKeyFor(type, projectId, item.record_id),
    type,
    title,
    fields: {
      id: item.record_id,
      record_type: type,
      project_id: projectId,
      status: str(pick('status')),
      priority: str(pick('priority')),
      category: str(pick('category')),
      checkout_state: str(pick('checkout_state')),
      components: list(pick('components')),
      tags: list(pick('tags')),
      title,
      updated_at: item.updated_at ?? undefined,
      created_at: str(pick('created_at')),
    },
    updatedAt: item.updated_at ?? null,
    version,
  }
}

export interface CorpusFetchers {
  corpus(params: { cursor?: string; limit: number }, signal?: AbortSignal): Promise<FeedCorpusPage>
  delta(cursors: { since: number; docSince: number }, signal?: AbortSignal): Promise<FeedDeltaPage>
}

const defaultFetchers: CorpusFetchers = {
  corpus: (params, signal) => fetchFeedCorpusPage(params, signal ? { signal } : undefined),
  delta: (cursors, signal) => fetchFeedDelta(cursors, signal ? { signal } : undefined),
}

const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0)

export function createEnceladusCorpusSource(fetchers: CorpusFetchers = defaultFetchers): CorpusSource<FeedCorpusItem> {
  return {
    id: CORPUS_ID,
    seqSpaces: [...SEQ_SPACES],
    async *seed(ctx): AsyncGenerator<SeedPage<FeedCorpusItem>> {
      let cursor: string | undefined
      // Each item carries the version_seq of its own space; the delta resumes from what the snapshot already holds.
      const high: Record<string, number> = { tracker: 0, document: 0 }
      for (;;) {
        const page = await fetchers.corpus({ ...(cursor ? { cursor } : {}), limit: SEED_PAGE_LIMIT }, ctx.signal)
        for (const item of page.items) {
          const space = item.source === 'document' || item.record_type === 'document' ? 'document' : 'tracker'
          high[space] = Math.max(high[space] ?? 0, num(item.version_seq))
        }
        yield { rows: page.items, cursors: { ...high } }
        if (!page.next_cursor) return
        cursor = page.next_cursor
      }
    },
    async since(cursors: Cursors, ctx): Promise<DeltaResult<FeedCorpusItem>> {
      const since = num(cursors.tracker)
      const docSince = num(cursors.document)
      const page = await fetchers.delta({ since, docSince }, ctx.signal)
      const windowed = page.truncated !== undefined || page.doc_truncated !== undefined
      return {
        upserts: page.items ?? [],
        deletes: (page.tombstones ?? []).map((t) => ({ key: t.record_key, version: String(t.version_seq) })),
        cursors: {
          tracker: Math.max(since, num(page.latest_version_seq)),
          document: Math.max(docSince, num(page.latest_doc_version_seq)),
        },
        ...(windowed ? { truncated: Boolean(page.truncated || page.doc_truncated) } : {}),
      }
    },
    mapRow: mapCorpusItem,
  }
}

let store: CorpusStore | null = null
/** One store for the app: the root provider seeds it, AppSync events merge into it, the launcher and routes read it. */
export function getEnceladusCorpusStore(): CorpusStore {
  if (!store) {
    store = new CorpusStore(createCorpusStorage(CORPUS_ID), {
      budget: CORPUS_BUDGET,
      seqSpaces: [...SEQ_SPACES],
      dropOnLoad: (row) => row.id === DOCUMENT_COUNTER_SENTINEL_ID,
    })
  }
  return store
}
export function resetEnceladusCorpusStoreForTests(): void {
  store = null
}

/**
 * AppSync event -> corpus change. Events carry only governed headline fields, so an event merges ONTO the stored row
 * (ENC-ISS-718/719: it must not stomp status/priority/updated_at with a thin projection); a removal tombstones with the
 * stored row's version so a strictly newer write (un-archive) can lift it.
 */
export function liveChangeFromEvent(
  event: FeedRealtimeEvent,
  rows: readonly IndexRow[],
  projects: ProjectSummary[] = [],
): LiveChange | null {
  const type = String(event.record_type ?? '').toLowerCase()
  if (!VALID_TYPES.has(type) || event.recordId === DOCUMENT_COUNTER_SENTINEL_ID) return null
  const existing = rows.find((r) => r.id === event.recordId)
  if (event.action === 'removed') {
    return existing ? { remove: { key: existing.key ?? existing.id, ...(existing.version ? { version: existing.version } : {}) } } : null
  }
  const updatedAt = newer(event.recordUpdatedAt, existing?.updatedAt)
  const title = event.recordTitle || existing?.title || event.summary || event.recordId
  if (existing) {
    return {
      upsert: {
        ...existing,
        title,
        fields: {
          ...existing.fields,
          title,
          status: event.recordStatus ?? existing.fields.status,
          priority: event.recordPriority ?? existing.fields.priority,
          updated_at: updatedAt ?? existing.fields.updated_at,
        },
        updatedAt: updatedAt ?? existing.updatedAt ?? null,
        // unchanged version token: the event is a headline overlay, not a newer server version
        ...(existing.version ? { version: existing.version } : {}),
      },
    }
  }
  const projectId = (type === 'document' ? 'global' : resolveProjectFromRecordId(event.recordId, projects)) ?? 'enceladus'
  return {
    upsert: {
      id: event.recordId,
      key: rowKeyFor(type, projectId, event.recordId),
      type,
      title,
      fields: {
        id: event.recordId,
        record_type: type,
        project_id: projectId,
        status: event.recordStatus,
        priority: event.recordPriority,
        title,
        updated_at: updatedAt,
      },
      updatedAt: updatedAt ?? null,
      version: updatedAt ?? '0',
    },
  }
}

function newer(a?: string | null, b?: string | null): string | undefined {
  if (a && b) return a > b ? a : b
  return a ?? b ?? undefined
}

/** Bound to the app store; called by the realtime provider for every /feed/updates event. */
export function applyFeedEventToCorpus(event: FeedRealtimeEvent): Promise<number> {
  const s = getEnceladusCorpusStore()
  const projects = queryClient.getQueryData<ProjectSummary[]>(projectRegistryQueryOptions.queryKey) ?? []
  return createLiveApplier<FeedRealtimeEvent>(s, (e) => liveChangeFromEvent(e, s.rows(), projects))(event)
}

/** Instant header suggestions from the local index: id prefix first, then title substring. */
export function suggestRows(rows: readonly IndexRow[], text: string, limit = 8): IndexRow[] {
  const needle = text.trim().toLowerCase()
  if (!needle) return []
  const prefix: IndexRow[] = []
  const contains: IndexRow[] = []
  for (const row of rows) {
    if (prefix.length >= limit) break
    if (row.id.toLowerCase().startsWith(needle)) prefix.push(row)
    else if (contains.length < limit && (row.id.toLowerCase().includes(needle) || row.title.toLowerCase().includes(needle))) contains.push(row)
  }
  return [...prefix, ...contains].slice(0, limit)
}
