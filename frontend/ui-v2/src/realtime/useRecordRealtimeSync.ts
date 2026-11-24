import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { recordKeys } from '../api/queryOptions'
import { getCacheEngine } from '../sync/cacheEngine'
import { shouldAcceptVersion, versionSeqFromUpdatedAt } from '../sync/recordKey'
import type { RecordType } from '../types/records'
import { normalizeRecordBody } from './normalizeRecordBody'
import { useRealtimeFeed } from './RealtimeFeedProvider'

/**
 * ENC-TSK-L29: while a tracker-record detail page is open, subscribe to its
 * `/records/{recordId}` full-body events and upsert them directly into the
 * Tier-2 mirror (ENC-TSK-L24) AND the live TanStack Query cache — no
 * follow-up fetch, and the open page updates in place. No-op if realtime is
 * disabled (RealtimeFeedProvider.watchRecord degrades to a safe no-op).
 */
export function useRecordRealtimeSync(
  recordType: Exclude<RecordType, 'document'>,
  projectId: string,
  recordId: string,
): void {
  const { watchRecord } = useRealtimeFeed()
  const queryClient = useQueryClient()

  useEffect(() => {
    const key = recordKeys.detail(recordType, projectId, recordId)
    return watchRecord(recordId, (event) => {
      if (event.action === 'removed' || !event.record) return
      // ENC-TSK-T30 (ENC-ISS-926): the event carries the raw stream image, not
      // the detail API's shape, so normalize it before it replaces the cache.
      const current = queryClient.getQueryData<{ updated_at?: string | null }>(key)
      const body = normalizeRecordBody(recordType, recordId, event.record, current)
      // ENC-TSK-M51 (B67 AC-8 part 3 / AC-2): the server-authoritative full body
      // wins, monotonically. A per-record `/records/{recordId}` frame is only
      // merged when its version is at least the currently-cached one, so an
      // out-of-order or duplicate event can never overwrite fresher data with a
      // stale (ghost) render. Full-body replacement is inherently idempotent, so
      // there are no duplicate rows to reconcile — a later event supersedes the
      // optimistic placeholder in place under its server-authoritative eventId.
      const incoming = versionSeqFromUpdatedAt(
        typeof body.updated_at === 'string' ? body.updated_at : '',
      )
      const currentSeq = current ? versionSeqFromUpdatedAt(current.updated_at) : undefined
      if (!shouldAcceptVersion(currentSeq, incoming)) return
      queryClient.setQueryData(key, body)
      void getCacheEngine().upsertTier2(projectId, recordId, body, incoming)
    })
  }, [watchRecord, queryClient, recordType, projectId, recordId])
}
