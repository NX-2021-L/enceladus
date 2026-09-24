import {
  fetchDocumentRecord,
  fetchTrackerRecord,
  SessionExpiredError,
} from '../api/client'
import { getCacheEngine } from './cacheEngine'
import { versionSeqFromUpdatedAt } from './recordKey'

type FetchInit = { signal?: AbortSignal; headers?: HeadersInit }

function updatedAtOf(fresh: unknown): string {
  return typeof fresh === 'object' && fresh && 'updated_at' in fresh
    ? String((fresh as { updated_at?: string | null }).updated_at ?? '')
    : ''
}

/**
 * ENC-TSK-M51 (B67 AC-8 part 2 / AC-14 / AC-17): the detail-route read is
 * NETWORK-FIRST, not cache-first. Every open of a record-detail page issues a
 * real per-record GET (`/api/v1/tracker/{project}/{type}/{id}`) so the page
 * reflects server-authoritative state on load — the original L24 read-through
 * returned the Tier-2 mirror body (seeded by the feed/corpus snapshot) and
 * NEVER hit the network, which is precisely the M51 defect ("hydrates solely
 * from feed/corpus cache; zero per-record GET on hard reload").
 *
 * The Tier-2 mirror is retained as the offline/degraded fallback, matching the
 * Workbox NetworkFirst policy on detail reads (AC-17): serve stale ONLY when
 * the network read fails. A cancelled request (AbortSignal) and an expired
 * session propagate rather than silently serving stale.
 */
async function readThroughNetworkFirst<T>(
  projectId: string,
  recordId: string,
  fetcher: () => Promise<T>,
  init?: FetchInit,
): Promise<T> {
  const engine = getCacheEngine()
  try {
    const fresh = await fetcher()
    await engine.upsertTier2(projectId, recordId, fresh, versionSeqFromUpdatedAt(updatedAtOf(fresh)))
    return fresh
  } catch (error) {
    // Never mask a cancelled load or a re-auth signal with a stale mirror read.
    if (init?.signal?.aborted || error instanceof SessionExpiredError) throw error
    const cached = await engine.getTier2Body(projectId, recordId)
    if (cached) return cached as T
    throw error
  }
}

export async function readThroughTrackerRecord<T>(
  recordType: 'task' | 'issue' | 'feature' | 'plan' | 'lesson',
  projectId: string,
  recordId: string,
  init?: FetchInit,
): Promise<T> {
  return readThroughNetworkFirst<T>(
    projectId,
    recordId,
    () => fetchTrackerRecord<T>(recordType, projectId, recordId, init),
    init,
  )
}

export async function readThroughDocumentRecord<T>(
  documentId: string,
  init?: FetchInit,
): Promise<T> {
  return readThroughNetworkFirst<T>(
    'global',
    documentId,
    () => fetchDocumentRecord<T>(documentId, init),
    init,
  )
}

export type { SessionExpiredError }
