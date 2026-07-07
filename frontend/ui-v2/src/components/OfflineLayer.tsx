import { useEffect, useState } from 'react'
import { Alert, Button, Flashbar, Modal } from '../design-system'
import { useOfflineStore } from '../store/offlineStore'
import { replayQueuedMutation } from '../api/mutations'
import { mergeConflictFields } from '../api/mutations'
import type { ConflictMergeState, MutationErrorState } from '../hooks/useRecordMutation'
import {
  registerConflictMergeHandler,
  registerMutationErrorHandler,
} from '../hooks/useRecordMutation'

const CLOSED_MUTATION_ERROR_STATE: MutationErrorState = {
  open: false,
  message: '',
  vars: null,
  retry: null,
}

export function OfflinePendingFlashbar() {
  const pendingCount = useOfflineStore((s) => s.pendingCount)
  const swUpdateReady = useOfflineStore((s) => s.swUpdateReady)
  const refreshPendingCount = useOfflineStore((s) => s.refreshPendingCount)
  const replayQueue = useOfflineStore((s) => s.replayQueue)
  const setSwUpdateReady = useOfflineStore((s) => s.setSwUpdateReady)

  useEffect(() => {
    void refreshPendingCount()
    const onOnline = () => {
      void replayQueue(replayQueuedMutation).then(() => refreshPendingCount())
    }
    window.addEventListener('online', onOnline)
    return () => window.removeEventListener('online', onOnline)
  }, [refreshPendingCount, replayQueue])

  const items = []
  if (pendingCount > 0) {
    items.push({
      id: 'offline-pending',
      type: 'in-progress' as const,
      header: `${pendingCount} change${pendingCount === 1 ? '' : 's'} pending sync`,
      content: 'Saved locally while offline. Mutations replay automatically when connectivity returns.',
      loading: true,
    })
  }
  if (swUpdateReady) {
    items.push({
      id: 'sw-update',
      type: 'info' as const,
      header: 'App update available',
      content: 'A new version is ready. Reload when your current edits are complete.',
      dismissible: true,
      onDismiss: () => setSwUpdateReady(false),
    })
  }

  if (items.length === 0) return null
  return <Flashbar items={items} />
}

/**
 * ENC-TSK-K23 (B67 AC-7): atomic-rollback surface for non-conflict mutation
 * failures (network error, 5xx, mid-flight session expiry). The optimistic
 * write already reverted synchronously in useRecordMutation's onError before
 * this ever renders — this is purely the user-facing "it failed, want to
 * retry?" notice, not part of the rollback itself.
 */
export function MutationErrorFlashbar() {
  const [state, setState] = useState<MutationErrorState>(CLOSED_MUTATION_ERROR_STATE)

  useEffect(() => {
    registerMutationErrorHandler(setState)
    return () => registerMutationErrorHandler(() => {})
  }, [])

  if (!state.open) return null

  const dismiss = () => setState(CLOSED_MUTATION_ERROR_STATE)

  const items = [
    {
      id: 'mutation-error',
      type: 'error' as const,
      header: 'Change failed to save',
      dismissible: true,
      onDismiss: dismiss,
      content: (
        <div className="flex items-center gap-3">
          <span>{state.message}</span>
          {state.retry ? (
            <Button
              variant="normal"
              recordId={state.vars?.recordId}
              onClick={() => {
                state.retry?.()
                dismiss()
              }}
            >
              Retry
            </Button>
          ) : null}
        </div>
      ),
    },
  ]

  return <Flashbar items={items} />
}

export function ConflictMergeModal() {
  const [state, setState] = useState<ConflictMergeState>({ open: false, error: null, vars: null })

  useEffect(() => {
    registerConflictMergeHandler(setState)
    return () => registerConflictMergeHandler(() => {})
  }, [])

  if (!state.open || !state.error || !state.vars) return null

  const server = state.error.details.current ?? {}
  const field = state.vars.field ?? 'status'
  const clientValue = state.vars.value
  const serverValue = server[field]
  const mode = mergeConflictFields(field, clientValue, server)

  return (
    <Modal
      visible
      header="Revision conflict — merge required"
      onDismiss={() => setState({ open: false, error: null, vars: null })}
      footer={
        <Button variant="primary" onClick={() => setState({ open: false, error: null, vars: null })}>
          Acknowledge
        </Button>
      }
    >
      <Alert type="warning" header="409 If-Match mismatch">
        {mode === 'server-wins'
          ? `Governance-critical field "${field}" — server value is authoritative.`
          : `Field "${field}" changed concurrently — review both values.`}
      </Alert>
      <div className="mt-4 grid gap-3 text-sm">
        <div>
          <strong>Your change</strong>
          <pre className="mt-1 rounded bg-slate-900/40 p-2 font-mono text-xs">{String(clientValue ?? '—')}</pre>
        </div>
        <div>
          <strong>Server state</strong>
          <pre className="mt-1 rounded bg-slate-900/40 p-2 font-mono text-xs">{String(serverValue ?? '—')}</pre>
        </div>
        <p className="text-slate-400">
          Expected revision {state.error.details.expected_revision ?? '—'}, server at{' '}
          {state.error.details.current_revision ?? '—'}.
        </p>
      </div>
    </Modal>
  )
}
