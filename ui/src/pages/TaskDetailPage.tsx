import { useState, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useTasks } from '../hooks/useTasks'
import { useIssues } from '../hooks/useIssues'
import { useFeatures } from '../hooks/useFeatures'
import { useRecordMutation } from '../hooks/useRecordMutation'
import { isMutationRetryExhaustedError } from '../api/mutations'
import { StatusChip } from '../components/shared/StatusChip'
import { PriorityBadge } from '../components/shared/PriorityBadge'
import { MarkdownRenderer } from '../components/shared/MarkdownRenderer'
import { HistoryFeed } from '../components/shared/HistoryFeed'
import { RelatedItems } from '../components/shared/RelatedItems'
import type { RecordInfo } from '../components/shared/RelatedItems'
import { ParentRecord } from '../components/shared/ParentRecord'
import { ChildRecords } from '../components/shared/ChildRecords'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { formatDate } from '../lib/formatters'
import { filterRelatedItems, getChildrenIds } from '../lib/relationshipFilters'

export function TaskDetailPage() {
  const { taskId } = useParams<{ taskId: string }>()
  const { allTasks, isPending, isError } = useTasks()
  const { allIssues } = useIssues()
  const { allFeatures } = useFeatures()
  const { mutate, isPending: isMutating } = useRecordMutation()

  const [confirming, setConfirming] = useState(false)
  const [confirmingReopen, setConfirmingReopen] = useState(false)
  const [showNote, setShowNote] = useState(false)
  const [note, setNote] = useState('')
  const [mutationError, setMutationError] = useState<string | null>(null)
  const [mutationSuccess, setMutationSuccess] = useState<string | null>(null)

  const task = allTasks.find((t) => t.task_id === taskId)

  const recordMap = useMemo<Record<string, RecordInfo>>(() => {
    const map: Record<string, RecordInfo> = {}
    for (const t of allTasks) map[t.task_id] = { title: t.title, status: t.status }
    for (const i of allIssues) map[i.issue_id] = { title: i.title, status: i.status }
    for (const f of allFeatures) map[f.feature_id] = { title: f.title, status: f.status }
    return map
  }, [allTasks, allIssues, allFeatures])

  if (isPending) return <LoadingState />
  if (isError) return <ErrorState />
  if (!task) return <ErrorState message="Task not found" />

  const canClose = task.status !== 'closed'
  const canReopen = task.status === 'closed'

  function handleReopen() {
    setMutationError(null)
    mutate(
      { projectId: task!.project_id, recordType: 'task', recordId: task!.task_id, action: 'reopen' },
      {
        onSuccess: () => {
          setConfirmingReopen(false)
          setMutationSuccess('Task reopened.')
          setTimeout(() => setMutationSuccess(null), 3000)
        },
        onError: (err) => {
          setConfirmingReopen(false)
          setMutationError(
            isMutationRetryExhaustedError(err)
              ? err.toDebugString()
              : (err.message ?? 'Reopen failed. Please try again.')
          )
        },
      }
    )
  }

  function handleClose() {
    setMutationError(null)
    mutate(
      { projectId: task!.project_id, recordType: 'task', recordId: task!.task_id, action: 'close' },
      {
        onSuccess: () => {
          setConfirming(false)
          setMutationSuccess('Task closed.')
          setTimeout(() => setMutationSuccess(null), 3000)
        },
        onError: (err) => {
          setConfirming(false)
          setMutationError(
            isMutationRetryExhaustedError(err)
              ? err.toDebugString()
              : (err.message ?? 'Close failed. Please try again.')
          )
        },
      }
    )
  }

  function handleSubmitNote() {
    if (!note.trim()) return
    setMutationError(null)
    mutate(
      { projectId: task!.project_id, recordType: 'task', recordId: task!.task_id, action: 'note', note },
      {
        onSuccess: () => {
          setShowNote(false)
          setNote('')
          setMutationSuccess('Note queued for agent processing.')
          setTimeout(() => setMutationSuccess(null), 4000)
        },
        onError: (err) => {
          setMutationError(
            isMutationRetryExhaustedError(err)
              ? err.toDebugString()
              : (err.message ?? 'Note failed. Please try again.')
          )
        },
      }
    )
  }

  return (
    <div className="p-4 space-y-4 pb-24">
      {/* Back link */}
      <Link to="/tasks" className="text-xs text-blue-400 inline-block">
        &larr; Tasks
      </Link>

      {/* Header */}
      <div>
        <Link
          to={`/projects/${task.project_id}`}
          className="text-xs text-blue-400 hover:text-blue-300 block mb-1"
        >
          {task.project_id}
        </Link>
        <span className="text-xs font-mono text-slate-500 block mb-1">{task.task_id}</span>
        <h1 className="text-lg font-semibold text-slate-100 mb-2">{task.title}</h1>
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <StatusChip status={task.status} />
          <PriorityBadge priority={task.priority} />
          {task.assigned_to && (
            <span className="text-xs text-slate-400">→ {task.assigned_to}</span>
          )}
        </div>
        <div className="flex gap-4 text-xs text-slate-500">
          <span>Created {formatDate(task.created_at)}</span>
          <span>Updated {formatDate(task.updated_at)}</span>
        </div>

        {/* Action bar */}
        <div className="flex items-center gap-2 mt-3">
          {canClose && !confirming && (
            <button
              onClick={() => setConfirming(true)}
              className="text-xs px-3 py-1.5 rounded-full bg-emerald-900/60 text-emerald-300 border border-emerald-700 hover:bg-emerald-800/70 transition-colors"
            >
              ✓ Close
            </button>
          )}
          {confirming && (
            <span className="text-xs text-slate-300 flex items-center gap-2">
              Close this task?
              <button
                onClick={handleClose}
                disabled={isMutating}
                className="text-emerald-400 hover:text-emerald-300 disabled:opacity-50"
              >
                {isMutating ? 'Closing…' : 'Confirm'}
              </button>
              <button
                onClick={() => setConfirming(false)}
                className="text-slate-500 hover:text-slate-400"
              >
                Cancel
              </button>
            </span>
          )}
          {canReopen && !confirmingReopen && (
            <button
              onClick={() => setConfirmingReopen(true)}
              className="text-xs px-3 py-1.5 rounded-full bg-amber-900/60 text-amber-300 border border-amber-700 hover:bg-amber-800/70 transition-colors"
            >
              Reopen
            </button>
          )}
          {confirmingReopen && (
            <span className="text-xs text-slate-300 flex items-center gap-2">
              Reopen this task?
              <button
                onClick={handleReopen}
                disabled={isMutating}
                className="text-amber-400 hover:text-amber-300 disabled:opacity-50"
              >
                {isMutating ? 'Reopening…' : 'Confirm'}
              </button>
              <button
                onClick={() => setConfirmingReopen(false)}
                className="text-slate-500 hover:text-slate-400"
              >
                Cancel
              </button>
            </span>
          )}
          <button
            onClick={() => { setShowNote(true); setMutationError(null) }}
            className="text-xs px-3 py-1.5 rounded-full bg-slate-700 text-slate-300 border border-slate-600 hover:bg-slate-600 transition-colors"
          >
            ✏ Note
          </button>
        </div>
        {mutationSuccess && (
          <p className="text-xs text-emerald-400 mt-1">{mutationSuccess}</p>
        )}
        {mutationError && (
          <p className="text-xs text-red-400 mt-1 whitespace-pre-wrap font-mono">{mutationError}</p>
        )}
      </div>

      {/* Parent Record */}
      {task.parent && (
        <ParentRecord
          parentId={task.parent}
          allTasks={allTasks}
          allIssues={allIssues}
          allFeatures={allFeatures}
        />
      )}

      {/* Child Records */}
      <ChildRecords
        recordId={task.task_id}
        allTasks={allTasks}
        allIssues={allIssues}
        allFeatures={allFeatures}
      />

      {/* Description */}
      {task.description && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Description
          </h3>
          <MarkdownRenderer content={task.description} />
        </div>
      )}

      {/* Checklist */}
      {task.checklist && task.checklist.length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Checklist ({task.checklist_done}/{task.checklist_total})
          </h3>
          <ul className="space-y-1.5">
            {task.checklist.map((item, i) => {
              const isDone = item.trim().toUpperCase().startsWith('DONE')
              return (
                <li key={i} className="flex items-start gap-2 text-sm">
                  <span className={`flex-shrink-0 mt-0.5 ${isDone ? 'text-emerald-400' : 'text-slate-600'}`}>
                    {isDone ? '✓' : '○'}
                  </span>
                  <span className={isDone ? 'text-slate-500 line-through' : 'text-slate-300'}>
                    {item}
                  </span>
                </li>
              )
            })}
          </ul>
        </div>
      )}

      {/* Related Items — ENC-FTR-014: De-duplicated (excludes parent/children) */}
      <div className="bg-slate-800 rounded-lg p-4">
        <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
          Related Items
        </h3>
        {useMemo(() => {
          // Get all children IDs to exclude from related items (de-duplication)
          const childrenIds = getChildrenIds(task.task_id, allTasks)
            .concat(getChildrenIds(task.task_id, allIssues))
            .concat(getChildrenIds(task.task_id, allFeatures))

          // Filter related items to exclude parent and children
          const filteredFeatures = filterRelatedItems(task.related_feature_ids ?? [], task.parent, childrenIds)
          const filteredTasks = filterRelatedItems(task.related_task_ids ?? [], task.parent, childrenIds)
          const filteredIssues = filterRelatedItems(task.related_issue_ids ?? [], task.parent, childrenIds)

          const hasRelated = filteredFeatures.length > 0 || filteredTasks.length > 0 || filteredIssues.length > 0

          return (
            <>
              {hasRelated ? (
                <RelatedItems
                  groups={[
                    { label: 'Features', ids: filteredFeatures, routePrefix: '/features' },
                    { label: 'Tasks', ids: filteredTasks, routePrefix: '/tasks' },
                    { label: 'Issues', ids: filteredIssues, routePrefix: '/issues' },
                  ]}
                  recordMap={recordMap}
                />
              ) : (
                <p className="text-sm text-slate-500">No related items.</p>
              )}
            </>
          )
        }, [task, allTasks, allIssues, allFeatures, recordMap])}
      </div>

      {/* History */}
      <div className="bg-slate-800 rounded-lg p-4">
        <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
          History
        </h3>
        <HistoryFeed entries={task.history ?? []} />
      </div>

      {/* Note bottom sheet overlay */}
      {showNote && (
        <div className="fixed inset-0 z-50 flex flex-col justify-end bg-black/60">
          <div className="bg-slate-800 rounded-t-2xl p-5 space-y-3 shadow-2xl">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-100">Add Update Note</h3>
              <button
                onClick={() => { setShowNote(false); setNote(''); setMutationError(null) }}
                className="text-slate-500 hover:text-slate-300 text-lg"
              >
                ✕
              </button>
            </div>
            <p className="text-xs text-slate-400">
              This note will be queued for the next agent session to process and integrate.
            </p>
            <textarea
              rows={5}
              maxLength={2000}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Describe what changed, what's needed, or any context…"
              className="w-full bg-slate-700 text-slate-100 text-sm rounded-lg p-3 border border-slate-600 focus:outline-none focus:border-blue-500 resize-none"
              autoFocus
            />
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-500">{note.length}/2000</span>
              <div className="flex gap-2">
                <button
                  onClick={() => { setShowNote(false); setNote(''); setMutationError(null) }}
                  className="text-xs px-4 py-2 rounded-full text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSubmitNote}
                  disabled={!note.trim() || isMutating}
                  className="text-xs px-4 py-2 rounded-full bg-blue-700 text-white hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {isMutating ? 'Saving…' : 'Submit'}
                </button>
              </div>
            </div>
            {mutationError && (
              <p className="text-xs text-red-400">{mutationError}</p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
