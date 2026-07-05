import {
  fetchDocumentRecord,
  fetchTrackerRecord,
  type SessionExpiredError,
} from '../api/client'
import { getCacheEngine } from './cacheEngine'
import { versionSeqFromUpdatedAt } from './recordKey'

type FetchInit = { signal?: AbortSignal; headers?: HeadersInit }

export async function readThroughTrackerRecord<T>(
  recordType: 'task' | 'issue' | 'feature' | 'plan' | 'lesson',
  projectId: string,
  recordId: string,
  init?: FetchInit,
): Promise<T> {
  const engine = getCacheEngine()
  const cached = await engine.getTier2Body(projectId, recordId)
  if (cached) return cached as T

  const fresh = await fetchTrackerRecord<T>(recordType, projectId, recordId, init)
  const updatedAt =
    typeof fresh === 'object' && fresh && 'updated_at' in fresh
      ? String((fresh as { updated_at?: string | null }).updated_at ?? '')
      : ''
  await engine.upsertTier2(projectId, recordId, fresh, versionSeqFromUpdatedAt(updatedAt))
  return fresh
}

export async function readThroughDocumentRecord<T>(
  documentId: string,
  init?: FetchInit,
): Promise<T> {
  const engine = getCacheEngine()
  const cached = await engine.getTier2Body('global', documentId)
  if (cached) return cached as T

  const fresh = await fetchDocumentRecord<T>(documentId, init)
  const updatedAt =
    typeof fresh === 'object' && fresh && 'updated_at' in fresh
      ? String((fresh as { updated_at?: string | null }).updated_at ?? '')
      : ''
  await engine.upsertTier2('global', documentId, fresh, versionSeqFromUpdatedAt(updatedAt))
  return fresh
}

export type { SessionExpiredError }
