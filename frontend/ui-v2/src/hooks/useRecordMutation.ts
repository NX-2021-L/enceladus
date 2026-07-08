import { useEffect, useRef } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  closeRecord,
  mergeConflictFields,
  readSyncVersion,
  setCheckout,
  setField,
  submitNote,
  submitWorklog,
  type MutationResult,
  type RevisionConflictError,
  isRevisionConflictError,
} from '../api/mutations'
import { SessionExpiredError } from '../api/client'
import { recordKeys } from '../api/queryOptions'
import { feedCorpusKeys } from '../api/feedCorpusQueryOptions'
import type { FeedCorpusPage } from '../sync/types'

type RecordType = 'task' | 'issue' | 'feature' | 'plan'

interface MutationVars {
  projectId: string
  recordType: RecordType
  recordId: string
  action: 'close' | 'note' | 'set_field' | 'worklog' | 'checkout' | 'release'
  note?: string
  field?: string
  value?: string
  syncVersion?: number
  /** ENC-TSK-M33 -- forwarded to `setField` as `transition_evidence` for
   *  state-aware advance (user_initiated) / revert (revert_reason) writes. */
  transitionEvidence?: Record<string, unknown>
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
 * ENC-TSK-K23 (B67 AC-7): non-conflict mutation failures (network error, 5xx,
 * session expiry mid-flight) surface here as a design-system Flashbar with a
 * Retry action — distinct from the 409 revision-conflict surface above,
 * which needs a merge decision rather than a blind resubmit.
 */
export interface MutationErrorState {
  open: boolean
  message: string
  vars: MutationVars | null
  retry: (() => void) | null
}

let mutationErrorHandler: ((state: MutationErrorState) => void) | null = null

export function registerMutationErrorHandler(handler: (state: MutationErrorState) => void): void {
  mutationErrorHandler = handler
}

interface FeedSnapshotEntry {
  key: readonly unknown[]
  value: FeedCorpusPage | undefined
}

interface MutationSnapshot {
  detailKey: readonly unknown[]
  detailValue: unknown
  feedEntries: FeedSnapshotEntry[]
}

/** Step 3 helper — the optimistic patch for a given action, applied to whatever
 * shape the detail cache currently holds (Task | Issue | Feature | Plan all
 * share `status`/arbitrary-field semantics at the tracker-record level). */
function applyOptimisticPatch(current: unknown, vars: MutationVars): unknown {
  if (!current || typeof current !== 'object') return current
  const base = current as Record<string, unknown>
  if (vars.action === 'close') {
    return { ...base, status: 'closed' }
  }
  if (vars.action === 'set_field' && vars.field && vars.value !== undefined) {
    return { ...base, [vars.field]: vars.value }
  }
  return current
}

function applyOptimisticFeedPatch(page: FeedCorpusPage, vars: MutationVars): FeedCorpusPage {
  let changed = false
  const items = page.items.map((item) => {
    if (item.record_id !== vars.recordId || item.record_type !== vars.recordType) return item
    changed = true
    if (vars.action === 'close') {
      return { ...item, attrs: { ...item.attrs, status: 'closed' } }
    }
    if (vars.action === 'set_field' && vars.field) {
      return { ...item, attrs: { ...item.attrs, [vars.field]: vars.value } }
    }
    return item
  })
  return changed ? { ...page, items } : page
}

/**
 * Optimistic tracker mutations (ENC-TSK-K23 / B67 AC-5/6/7), built on the
 * If-Match revision contract (ENC-TSK-L47 / K25 AC-3).
 *
 * Five-step onMutate sequence per DOC-E470AC8CE9A8 §3.1:
 *   1. cancel outgoing refetches for every cache this mutation touches
 *   2. snapshot current values for atomic rollback
 *   3. surgically write the optimistic value into cache
 *   4. return the snapshot as onError's rollback context
 *   5. onSettled invalidates regardless of outcome, reconciling with server truth
 *
 * Cross-page propagation (AC-6): the task detail page and the parent plan
 * page both read the SAME `recordKeys.detail(...)` cache entry — a Plan
 * record references child tasks by ID (`objectives_set`), it does not embed
 * them — so one `setQueryData` call on that key is what makes both views
 * reflect a transition in the same render pass, no second write needed. The
 * feed corpus cache is a separate, list-shaped cache, so it gets its own
 * predicate-matched `setQueriesData` patch (step 3) and its own snapshot
 * entries (step 2 / rollback).
 */
export function useRecordMutation() {
  const qc = useQueryClient()
  const mutationRef = useRef<ReturnType<typeof useMutation<MutationResult, Error, MutationVars, MutationSnapshot>> | null>(
    null,
  )

  const mutation = useMutation<MutationResult, Error, MutationVars, MutationSnapshot>({
    mutationFn: async (vars) => {
      const revision = vars.syncVersion ?? undefined
      if (vars.action === 'close') {
        return closeRecord(vars.projectId, vars.recordType, vars.recordId, revision)
      }
      if (vars.action === 'note') {
        return submitNote(vars.projectId, vars.recordType, vars.recordId, vars.note ?? '', revision)
      }
      if (vars.action === 'worklog') {
        return submitWorklog(vars.projectId, vars.recordType, vars.recordId, vars.note ?? '', revision)
      }
      if (vars.action === 'checkout') {
        return setCheckout(vars.projectId, vars.recordType, vars.recordId, true)
      }
      if (vars.action === 'release') {
        return setCheckout(vars.projectId, vars.recordType, vars.recordId, false)
      }
      return setField(
        vars.projectId,
        vars.recordType,
        vars.recordId,
        vars.field!,
        vars.value!,
        revision,
        vars.transitionEvidence,
      )
    },

    onMutate: async (vars) => {
      const detailKey = recordKeys.detail(vars.recordType, vars.projectId, vars.recordId)
      const touchesDetail = vars.action === 'close' || vars.action === 'set_field'

      // Step 1: cancel outgoing refetches so a stale in-flight response can't
      // clobber the optimistic write below.
      await qc.cancelQueries({ queryKey: detailKey })
      if (touchesDetail) {
        await qc.cancelQueries({ queryKey: feedCorpusKeys.all })
      }

      // Step 2: snapshot every cache entry we're about to touch.
      const detailValue = qc.getQueryData(detailKey)
      const feedEntries: FeedSnapshotEntry[] = touchesDetail
        ? qc
            .getQueriesData<FeedCorpusPage>({ queryKey: feedCorpusKeys.all })
            .map(([key, value]) => ({ key, value }))
        : []

      // Step 3: surgical optimistic write. `note` has no visible field to
      // patch pre-emptively (worklog entries render from server history).
      if (touchesDetail) {
        if (detailValue !== undefined) {
          qc.setQueryData(detailKey, applyOptimisticPatch(detailValue, vars))
        }
        qc.setQueriesData<FeedCorpusPage>({ queryKey: feedCorpusKeys.all }, (page) =>
          page ? applyOptimisticFeedPatch(page, vars) : page,
        )
      }

      // Step 4: return the full snapshot for atomic rollback in onError.
      return { detailKey, detailValue, feedEntries }
    },

    onError: (error, vars, context) => {
      if (isRevisionConflictError(error)) {
        conflictHandler?.({ open: true, error, vars })
        return
      }

      // Step 4 (continued): atomic rollback — every cache entry touched in
      // onMutate is restored in one pass, never a partial revert.
      if (context) {
        if (context.detailValue !== undefined) {
          qc.setQueryData(context.detailKey, context.detailValue)
        }
        for (const entry of context.feedEntries) {
          qc.setQueryData(entry.key, entry.value)
        }
      }

      mutationErrorHandler?.({
        open: true,
        message:
          error instanceof SessionExpiredError
            ? 'Session expired — sign in again to retry.'
            : error.message || 'Change failed to save.',
        vars,
        retry: () => mutationRef.current?.mutate(vars),
      })
    },

    onSettled: (_data, _error, vars) => {
      // Step 5: reconcile with server truth regardless of outcome. On
      // success this picks up server-computed fields (history, updated_at)
      // beyond what step 3 patched; on failure the just-restored snapshot
      // may itself be stale, so this is not redundant with the rollback.
      void qc.invalidateQueries({
        queryKey: recordKeys.detail(vars.recordType, vars.projectId, vars.recordId),
      })
      if (
        vars.action === 'close' ||
        vars.action === 'set_field' ||
        vars.action === 'checkout' ||
        vars.action === 'release'
      ) {
        // Checkout/release changes the feed card's session + checkout chips
        // (ENC-TSK-M33 chip-row parity) even though it isn't a status write.
        void qc.invalidateQueries({ queryKey: feedCorpusKeys.all })
      }
    },
  })

  // Refs must not be written during render (React rules-of-hooks) — the
  // retry closure in onError only ever runs from a user-triggered event
  // (clicking Retry) well after mount, so committing this in an effect is
  // still ready by the time it's needed.
  useEffect(() => {
    mutationRef.current = mutation
  })

  return mutation
}

export function extractRevisionFromRecord(record: unknown): number | undefined {
  return readSyncVersion(record)
}

export { mergeConflictFields, isRevisionConflictError }
