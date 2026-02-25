import { useState, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useTasks } from '../hooks/useTasks'
import { useIssues } from '../hooks/useIssues'
import { useFeatures } from '../hooks/useFeatures'
import { useRecordMutation } from '../hooks/useRecordMutation'
import { isMutationRetryExhaustedError } from '../api/mutations'
import { StatusChip } from '../components/shared/StatusChip'
import { PriorityBadge } from '../components/shared/PriorityBadge'
import { GitHubLinkBadge } from '../components/shared/GitHubLinkBadge'
import { GitHubOverlay } from '../components/shared/GitHubOverlay'
import { MarkdownRenderer } from '../components/shared/MarkdownRenderer'
import { LifecycleActions } from '../components/shared/LifecycleActions'
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

  const [showNote, setShowNote] = useState(false)
  const [showGitHubLink, setShowGitHubLink] = useState(false)
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

  // ENC-FTR-014: Compute filtered related items (de-duplicated, excludes parent/children)
  const filteredRelated = useMemo(() => {
    if (!task) return { features: [] as string[], tasks: [] as string[], issues: [] as string[], hasRelated: false }
    const childrenIds = getChildrenIds(task.task_id, allTasks)
      .concat(getChildrenIds(task.task_id, allIssues))
      .concat(getChildrenIds(task.task_id, allFeatures))
    const features = filterRelatedItems(task.related_feature_ids ?? [], task.parent, childrenIds)
    const tasks = filterRelatedItems(task.related_task_ids ?? [], task.parent, childrenIds)
    const issues = filterRelatedItems(task.related_issue_ids ?? [], task.parent, childrenIds)
    return { features, tasks, issues, hasRelated: features.length > 0 || tasks.length > 0 || issues.length > 0 }
  }, [task, allTasks, allIssues, allFeatures])

  if (isPending) return <LoadingState />
  if (isError) return <ErrorState />
  if (!task) return <ErrorState message="Task not found" />

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
          {task.category && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-violet-500/20 text-violet-400">
              {task.category}
            </span>
          )}
          <GitHubLinkBadge url={task.github_issue_url} />
          {task.coordination && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-cyan-500/20 text-cyan-400" title="Part of multi-agent coordination">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-current opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-current" />
              </span>
              Coordination
            </span>
          )}
          {task.assigned_to && (
            <span className="text-xs text-slate-400">→ {task.assigned_to}</span>
          )}
        </div>
        <div className="flex gap-4 text-xs text-slate-500">
          <span>Created {formatDate(task.created_at)}</span>
          <span>Updated {formatDate(task.updated_at)}</span>
        </div>

        {/* Action bar */}
        <div className="flex items-center gap-2 mt-3 flex-wrap">
          <LifecycleActions
            recordType="task"
            currentStatus={task.status}
            projectId={task.project_id}
            recordId={task.task_id}
            onSuccess={(msg) => { setMutationSuccess(msg); setTimeout(() => setMutationSuccess(null), 3000) }}
            onError={(msg) => setMutationError(msg)}
          />
          <button
            onClick={() => { setShowNote(true); setMutationError(null) }}
            className="text-xs px-3 py-1.5 rounded-full bg-slate-700 text-slate-300 border border-slate-600 hover:bg-slate-600 transition-colors"
          >
            ✏ Note
          </button>
          {task.github_issue_url ? (
            <a
              href={task.github_issue_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs px-3 py-1.5 rounded-full bg-slate-700 text-slate-300 border border-slate-600 hover:bg-slate-600 transition-colors inline-flex items-center gap-1.5"
            >
              <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
              linked
            </a>
          ) : (
            <button
              onClick={() => { setShowGitHubLink(true); setMutationError(null) }}
              className="text-xs px-3 py-1.5 rounded-full bg-slate-700 text-slate-300 border border-slate-600 hover:bg-slate-600 transition-colors inline-flex items-center gap-1.5"
            >
              <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
              link to GitHub
            </button>
          )}
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

      {/* Intent (ENC-FTR-017 philosophy) */}
      {task.intent && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Intent
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed">{task.intent}</p>
        </div>
      )}

      {/* Description */}
      {task.description && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Description
          </h3>
          <MarkdownRenderer content={task.description} />
        </div>
      )}

      {/* Acceptance Criteria (ENC-FTR-017 philosophy) */}
      {task.acceptance_criteria && task.acceptance_criteria.length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Acceptance Criteria
          </h3>
          <ul className="space-y-1.5">
            {task.acceptance_criteria.map((criterion, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <span className="text-blue-400 flex-shrink-0 mt-0.5">&#x2022;</span>
                <span className="text-slate-300">{criterion}</span>
              </li>
            ))}
          </ul>
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
        {filteredRelated.hasRelated ? (
          <RelatedItems
            groups={[
              { label: 'Features', ids: filteredRelated.features, routePrefix: '/features' },
              { label: 'Tasks', ids: filteredRelated.tasks, routePrefix: '/tasks' },
              { label: 'Issues', ids: filteredRelated.issues, routePrefix: '/issues' },
            ]}
            recordMap={recordMap}
          />
        ) : (
          <p className="text-sm text-slate-500">No related items.</p>
        )}
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

      {/* GitHub overlay (link existing or create new) */}
      {showGitHubLink && (
        <GitHubOverlay
          projectId={task.project_id}
          recordType="task"
          recordId={task.task_id}
          recordTitle={task.title}
          recordDescription={task.description}
          recordPriority={task.priority}
          onClose={() => { setShowGitHubLink(false); setMutationError(null) }}
          onSuccess={(msg) => { setMutationSuccess(msg); setTimeout(() => setMutationSuccess(null), 4000) }}
          onError={setMutationError}
        />
      )}
    </div>
  )
}
