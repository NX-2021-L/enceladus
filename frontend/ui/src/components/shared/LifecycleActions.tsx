import { useState } from 'react'
import { useRecordMutation } from '../../hooks/useRecordMutation'
import { isMutationRetryExhaustedError } from '../../api/mutations'
import { TASK_STATUSES, ISSUE_STATUSES, FEATURE_STATUSES, STATUS_LABELS } from '../../lib/constants'

type RecordType = 'task' | 'issue' | 'feature'

const LIFECYCLE_MAP: Record<RecordType, readonly string[]> = {
  task: TASK_STATUSES,
  issue: ISSUE_STATUSES,
  feature: FEATURE_STATUSES,
}

function getNextStatus(recordType: RecordType, current: string): string | null {
  const stages = LIFECYCLE_MAP[recordType]
  const idx = (stages as readonly string[]).indexOf(current)
  if (idx < 0 || idx >= stages.length - 1) return null
  return stages[idx + 1]
}

function getPrevStatus(recordType: RecordType, current: string): string | null {
  const stages = LIFECYCLE_MAP[recordType]
  const idx = (stages as readonly string[]).indexOf(current)
  if (idx <= 0) return null
  return stages[idx - 1]
}

interface LifecycleActionsProps {
  recordType: RecordType
  currentStatus: string
  projectId: string
  recordId: string
  onSuccess: (msg: string) => void
  onError: (msg: string) => void
}

export function LifecycleActions({ recordType, currentStatus, projectId, recordId, onSuccess, onError }: LifecycleActionsProps) {
  const { mutate, isPending: isMutating } = useRecordMutation()
  const [modal, setModal] = useState<{ direction: 'forward' | 'backward'; targetStatus: string } | null>(null)
  const [note, setNote] = useState('')

  const next = getNextStatus(recordType, currentStatus)
  const prev = getPrevStatus(recordType, currentStatus)

  function handleSubmit() {
    if (!note.trim() || !modal) return
    const { direction, targetStatus } = modal

    // Step 1: Submit the update note
    mutate(
      { projectId, recordType, recordId, action: 'note', note },
      {
        onSuccess: () => {
          // Step 2: Change status
          const transitionEvidence = direction === 'backward'
            ? { revert_reason: note }
            : undefined

          mutate(
            {
              projectId, recordType, recordId,
              action: 'set_field',
              field: 'status',
              value: targetStatus,
              transitionEvidence,
            },
            {
              onSuccess: () => {
                const label = STATUS_LABELS[targetStatus] ?? targetStatus
                setModal(null)
                setNote('')
                onSuccess(`Status changed to ${label}.`)
              },
              onError: (err) => {
                setModal(null)
                setNote('')
                onError(
                  isMutationRetryExhaustedError(err)
                    ? err.toDebugString()
                    : (err.message ?? 'Status change failed.')
                )
              },
            }
          )
        },
        onError: (err) => {
          setModal(null)
          setNote('')
          onError(
            isMutationRetryExhaustedError(err)
              ? err.toDebugString()
              : (err.message ?? 'Note submission failed.')
          )
        },
      }
    )
  }

  return (
    <>
      {next && (
        <button
          onClick={() => { setModal({ direction: 'forward', targetStatus: next }); setNote('') }}
          className="text-xs px-3 py-1.5 rounded-full bg-emerald-900/60 text-emerald-300 border border-emerald-700 hover:bg-emerald-800/70 transition-colors"
        >
          {STATUS_LABELS[next] ?? next} →
        </button>
      )}
      {prev && (
        <button
          onClick={() => { setModal({ direction: 'backward', targetStatus: prev }); setNote('') }}
          className="text-xs px-3 py-1.5 rounded-full bg-amber-900/60 text-amber-300 border border-amber-700 hover:bg-amber-800/70 transition-colors"
        >
          ← {STATUS_LABELS[prev] ?? prev}
        </button>
      )}

      {/* Stage transition modal */}
      {modal && (
        <div className="fixed inset-0 z-50 flex flex-col justify-end bg-black/60">
          <div className="bg-slate-800 rounded-t-2xl p-5 space-y-3 shadow-2xl">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-100">
                {modal.direction === 'forward' ? 'Advance' : 'Revert'} to {STATUS_LABELS[modal.targetStatus] ?? modal.targetStatus}
              </h3>
              <button
                onClick={() => { setModal(null); setNote('') }}
                className="text-slate-500 hover:text-slate-300 text-lg"
              >
                ✕
              </button>
            </div>
            <p className="text-xs text-slate-400">
              {modal.direction === 'forward'
                ? 'Add an update note explaining why this is advancing.'
                : 'Add an update note explaining why this is being reverted.'}
            </p>
            <textarea
              rows={4}
              maxLength={2000}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder={modal.direction === 'forward'
                ? 'Why is this moving forward?'
                : 'Why is this being reverted?'}
              className="w-full bg-slate-700 text-slate-100 text-sm rounded-lg p-3 border border-slate-600 focus:outline-none focus:border-blue-500 resize-none"
              autoFocus
            />
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-500">{note.length}/2000</span>
              <div className="flex gap-2">
                <button
                  onClick={() => { setModal(null); setNote('') }}
                  className="text-xs px-4 py-2 rounded-full text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSubmit}
                  disabled={!note.trim() || isMutating}
                  className={`text-xs px-4 py-2 rounded-full text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors ${
                    modal.direction === 'forward'
                      ? 'bg-emerald-700 hover:bg-emerald-600'
                      : 'bg-amber-700 hover:bg-amber-600'
                  }`}
                >
                  {isMutating ? 'Saving...' : 'Submit'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
