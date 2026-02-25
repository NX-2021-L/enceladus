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
import { SeverityBadge } from '../components/shared/SeverityBadge'
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

export function IssueDetailPage() {
  const { issueId } = useParams<{ issueId: string }>()
  const { allTasks } = useTasks()
  const { allIssues, isPending, isError } = useIssues()
  const { allFeatures } = useFeatures()
  const { mutate, isPending: isMutating } = useRecordMutation()

  const [confirming, setConfirming] = useState(false)
  const [confirmingReopen, setConfirmingReopen] = useState(false)
  const [showNote, setShowNote] = useState(false)
  const [showGitHubLink, setShowGitHubLink] = useState(false)
  const [note, setNote] = useState('')
  const [mutationError, setMutationError] = useState<string | null>(null)
  const [mutationSuccess, setMutationSuccess] = useState<string | null>(null)

  const issue = allIssues.find((i) => i.issue_id === issueId)

  const recordMap = useMemo<Record<string, RecordInfo>>(() => {
    const map: Record<string, RecordInfo> = {}
    for (const t of allTasks) map[t.task_id] = { title: t.title, status: t.status }
    for (const i of allIssues) map[i.issue_id] = { title: i.title, status: i.status }
    for (const f of allFeatures) map[f.feature_id] = { title: f.title, status: f.status }
    return map
  }, [allTasks, allIssues, allFeatures])

  // ENC-FTR-014: Compute filtered related items (de-duplicated, excludes parent/children)
  const filteredRelated = useMemo(() => {
    if (!issue) return { features: [] as string[], tasks: [] as string[], issues: [] as string[], hasRelated: false }
    const childrenIds = getChildrenIds(issue.issue_id, allTasks)
      .concat(getChildrenIds(issue.issue_id, allIssues))
      .concat(getChildrenIds(issue.issue_id, allFeatures))
    const features = filterRelatedItems(issue.related_feature_ids ?? [], issue.parent, childrenIds)
    const tasks = filterRelatedItems(issue.related_task_ids ?? [], issue.parent, childrenIds)
    const issues = filterRelatedItems(issue.related_issue_ids ?? [], issue.parent, childrenIds)
    return { features, tasks, issues, hasRelated: features.length > 0 || tasks.length > 0 || issues.length > 0 }
  }, [issue, allTasks, allIssues, allFeatures])

  if (isPending) return <LoadingState />
  if (isError) return <ErrorState />
  if (!issue) return <ErrorState message="Issue not found" />

  const canClose = issue.status !== 'closed'
  const canReopen = issue.status === 'closed'

  function handleReopen() {
    setMutationError(null)
    mutate(
      { projectId: issue!.project_id, recordType: 'issue', recordId: issue!.issue_id, action: 'reopen' },
      {
        onSuccess: () => {
          setConfirmingReopen(false)
          setMutationSuccess('Issue reopened.')
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
      { projectId: issue!.project_id, recordType: 'issue', recordId: issue!.issue_id, action: 'close' },
      {
        onSuccess: () => {
          setConfirming(false)
          setMutationSuccess('Issue closed.')
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
      { projectId: issue!.project_id, recordType: 'issue', recordId: issue!.issue_id, action: 'note', note },
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
      <Link to="/issues" className="text-xs text-blue-400 inline-block">
        &larr; Issues
      </Link>

      {/* Header */}
      <div>
        <Link
          to={`/projects/${issue.project_id}`}
          className="text-xs text-blue-400 hover:text-blue-300 block mb-1"
        >
          {issue.project_id}
        </Link>
        <span className="text-xs font-mono text-slate-500 block mb-1">{issue.issue_id}</span>
        <h1 className="text-lg font-semibold text-slate-100 mb-2">{issue.title}</h1>
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <StatusChip status={issue.status} />
          <PriorityBadge priority={issue.priority} />
          <SeverityBadge severity={issue.severity} />
          <GitHubLinkBadge url={issue.github_issue_url} />
        </div>
        <div className="flex gap-4 text-xs text-slate-500">
          <span>Created {formatDate(issue.created_at)}</span>
          <span>Updated {formatDate(issue.updated_at)}</span>
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
              Close this issue?
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
              Reopen this issue?
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
          {issue.github_issue_url ? (
            <a
              href={issue.github_issue_url}
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
      {issue.parent && (
        <ParentRecord
          parentId={issue.parent}
          allTasks={allTasks}
          allIssues={allIssues}
          allFeatures={allFeatures}
        />
      )}

      {/* Child Records */}
      <ChildRecords
        recordId={issue.issue_id}
        allTasks={allTasks}
        allIssues={allIssues}
        allFeatures={allFeatures}
      />

      {/* Description */}
      {issue.description && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Description
          </h3>
          <MarkdownRenderer content={issue.description} />
        </div>
      )}

      {/* Hypothesis */}
      {issue.hypothesis && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Hypothesis
          </h3>
          <MarkdownRenderer content={issue.hypothesis} />
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
        <HistoryFeed entries={issue.history ?? []} />
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
              <p className="text-xs text-red-400 whitespace-pre-wrap font-mono">{mutationError}</p>
            )}
          </div>
        </div>
      )}

      {/* GitHub overlay (link existing or create new) */}
      {showGitHubLink && (
        <GitHubOverlay
          projectId={issue.project_id}
          recordType="issue"
          recordId={issue.issue_id}
          recordTitle={issue.title}
          recordDescription={issue.description}
          recordPriority={issue.priority}
          onClose={() => { setShowGitHubLink(false); setMutationError(null) }}
          onSuccess={(msg) => { setMutationSuccess(msg); setTimeout(() => setMutationSuccess(null), 4000) }}
          onError={setMutationError}
        />
      )}
    </div>
  )
}
