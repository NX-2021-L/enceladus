/**
 * useRecordMutation — TanStack Query mutation hook for close and note actions.
 *
 * Optimistically updates the relevant feed cache on close so the UI reflects
 * the new status immediately without waiting for S3 sync. On error, rolls back
 * to the pre-mutation snapshot. On success, invalidates the feed query so
 * background refetch gets the canonical server state.
 */

import { useMutation, useQueryClient } from '@tanstack/react-query'
import { closeRecord, submitNote, reopenRecord, setField, setCheckout } from '../api/mutations'
import type { MutationResult } from '../api/mutations'
import { feedKeys } from '../api/feeds'

type RecordType = 'task' | 'issue' | 'feature'

interface MutationVars {
  projectId: string
  recordType: RecordType
  recordId: string
  action: 'close' | 'note' | 'reopen' | 'set_field' | 'checkout' | 'release'
  note?: string
  field?: string
  value?: string
  transitionEvidence?: Record<string, unknown>
}

/**
 * Generic record mutation hook.
 *
 * For 'close' action: applies an optimistic status update to the cached feed.
 * For 'note' action: no optimistic update (field not visible in PWA); just fires and invalidates.
 *
 * Returns a standard TanStack useMutation result plus:
 *   mutate({ projectId, recordType, recordId, action, note? })
 */
export function useRecordMutation() {
  const qc = useQueryClient()
  const feedKeyMap: Record<RecordType, readonly unknown[]> = {
    task: feedKeys.tasks,
    issue: feedKeys.issues,
    feature: feedKeys.features,
  }
  const idFieldMap: Record<RecordType, string> = {
    task: 'task_id',
    issue: 'issue_id',
    feature: 'feature_id',
  }
  const pluralMap: Record<RecordType, string> = {
    task: 'tasks',
    issue: 'issues',
    feature: 'features',
  }

  return useMutation<MutationResult, Error, MutationVars, { snapshot: unknown; feedKey: readonly unknown[] }>({
    mutationFn: ({ projectId, recordType, recordId, action, note, field, value, transitionEvidence }) => {
      if (action === 'close') return closeRecord(projectId, recordType, recordId)
      if (action === 'reopen') return reopenRecord(projectId, recordType, recordId)
      if (action === 'checkout') return setCheckout(projectId, recordType, recordId, true)
      if (action === 'release') return setCheckout(projectId, recordType, recordId, false)
      if (action === 'set_field') {
        const extras = transitionEvidence ? { transition_evidence: transitionEvidence } : undefined
        return setField(projectId, recordType, recordId, field!, value!, extras)
      }
      return submitNote(projectId, recordType, recordId, note ?? '')
    },

    onMutate: async ({ recordType, recordId, action, field, value }) => {
      // Determine target status for optimistic update
      let targetStatus: string | undefined
      if (action === 'close') {
        const closedStatusMap: Record<RecordType, string> = { task: 'closed', issue: 'closed', feature: 'completed' }
        targetStatus = closedStatusMap[recordType]
      } else if (action === 'reopen') {
        const defaultStatusMap: Record<RecordType, string> = { task: 'open', issue: 'open', feature: 'planned' }
        targetStatus = defaultStatusMap[recordType]
      } else if (action === 'set_field' && field === 'status' && value) {
        targetStatus = value
      }

      if (!targetStatus) return { snapshot: undefined, feedKey: [] }

      const feedKey = feedKeyMap[recordType]
      const idField = idFieldMap[recordType]

      // Cancel any in-flight refetches so they don't clobber our optimistic update
      await qc.cancelQueries({ queryKey: feedKey })

      // Snapshot the current cache value
      const snapshot = qc.getQueryData(feedKey)

      // Apply optimistic update
      qc.setQueryData(feedKey, (old: any) => {
        if (!old) return old
        const listKey = pluralMap[recordType]
        return {
          ...old,
          [listKey]: old[listKey]?.map((item: any) =>
            item[idField] === recordId
              ? { ...item, status: targetStatus }
              : item
          ) ?? [],
        }
      })

      return { snapshot, feedKey }
    },

    onError: (_err, _vars, context) => {
      // Rollback optimistic update
      if (context?.snapshot !== undefined && context?.feedKey?.length) {
        qc.setQueryData(context.feedKey, context.snapshot)
      }
    },

    onSuccess: (data, { recordType, recordId, action, field }) => {
      const feedKey = feedKeyMap[recordType]
      const isStatusChange = action === 'close' || action === 'reopen' || (action === 'set_field' && field === 'status')

      // Keep local status aligned with mutation response and avoid immediate
      // overwrite by stale S3 feeds while sync propagation catches up.
      if (isStatusChange && data.updated_status) {
        const idField = idFieldMap[recordType]
        const listKey = pluralMap[recordType]
        qc.setQueryData(feedKey, (old: any) => {
          if (!old) return old
          return {
            ...old,
            [listKey]: old[listKey]?.map((item: any) =>
              item[idField] === recordId
                ? { ...item, status: data.updated_status, updated_at: data.updated_at }
                : item
            ) ?? [],
          }
        })
        setTimeout(() => {
          qc.invalidateQueries({ queryKey: feedKey })
        }, 15_000)
        return
      }

      qc.invalidateQueries({ queryKey: feedKey })
    },
  })
}
