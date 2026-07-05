import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  closeRecord,
  mergeConflictFields,
  readSyncVersion,
  setField,
  submitNote,
  type MutationResult,
  type RevisionConflictError,
  isRevisionConflictError,
} from '../api/mutations'
import { recordKeys } from '../api/queryOptions'

type RecordType = 'task' | 'issue' | 'feature' | 'plan'

interface MutationVars {
  projectId: string
  recordType: RecordType
  recordId: string
  action: 'close' | 'note' | 'set_field'
  note?: string
  field?: string
  value?: string
  syncVersion?: number
}

export interface ConflictMergeState {
  open: boolean
  error: RevisionConflictError | null
  vars: MutationVars | null
}

let conflictHandler: ((state: ConflictMergeState) => void) | null = null

export function registerConflictMergeHandler(handler: (state: ConflictMergeState) => void): void {
  conflictHandler = handler
}

/**
 * Optimistic tracker mutations with If-Match revision headers (K25 / K23 pattern).
 */
export function useRecordMutation() {
  const qc = useQueryClient()

  return useMutation<MutationResult, Error, MutationVars>({
    mutationFn: async (vars) => {
      const revision = vars.syncVersion ?? undefined
      if (vars.action === 'close') {
        return closeRecord(vars.projectId, vars.recordType, vars.recordId, revision)
      }
      if (vars.action === 'note') {
        return submitNote(vars.projectId, vars.recordType, vars.recordId, vars.note ?? '', revision)
      }
      return setField(
        vars.projectId,
        vars.recordType,
        vars.recordId,
        vars.field!,
        vars.value!,
        revision,
      )
    },
    onMutate: async (vars) => {
      if (vars.action !== 'set_field' || vars.field !== 'status' || !vars.value) {
        return { snapshot: undefined }
      }
      const key = recordKeys.detail(vars.recordType, vars.projectId, vars.recordId)
      await qc.cancelQueries({ queryKey: key })
      const snapshot = qc.getQueryData(key)
      return { snapshot }
    },
    onError: (error, vars, context) => {
      if (isRevisionConflictError(error)) {
        conflictHandler?.({ open: true, error, vars })
        return
      }
      if (context?.snapshot !== undefined && vars) {
        qc.setQueryData(
          recordKeys.detail(vars.recordType, vars.projectId, vars.recordId),
          context.snapshot,
        )
      }
    },
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({
        queryKey: recordKeys.detail(vars.recordType, vars.projectId, vars.recordId),
      })
    },
  })
}

export function extractRevisionFromRecord(record: unknown): number | undefined {
  return readSyncVersion(record)
}

export { mergeConflictFields, isRevisionConflictError }
