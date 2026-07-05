import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { recordKeys } from '../api/queryOptions'
import { getCacheEngine } from '../sync/cacheEngine'
import { versionSeqFromUpdatedAt } from '../sync/recordKey'
import type { RecordType } from '../types/records'
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
    return watchRecord(recordId, (event) => {
      if (event.action === 'removed' || !event.record) return
      const body = event.record
      const updatedAt = typeof body.updated_at === 'string' ? body.updated_at : ''
      queryClient.setQueryData(recordKeys.detail(recordType, projectId, recordId), body)
      void getCacheEngine().upsertTier2(projectId, recordId, body, versionSeqFromUpdatedAt(updatedAt))
    })
  }, [watchRecord, queryClient, recordType, projectId, recordId])
}
