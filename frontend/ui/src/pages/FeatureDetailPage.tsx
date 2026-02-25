import { useMemo, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useFeatures } from '../hooks/useFeatures'
import { useTasks } from '../hooks/useTasks'
import { useIssues } from '../hooks/useIssues'
import { useRecordMutation } from '../hooks/useRecordMutation'
import { isMutationRetryExhaustedError } from '../api/mutations'
import { StatusChip } from '../components/shared/StatusChip'
import { GitHubLinkBadge } from '../components/shared/GitHubLinkBadge'
import { GitHubOverlay } from '../components/shared/GitHubOverlay'
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

export function FeatureDetailPage() {
  const { featureId } = useParams<{ featureId: string }>()
  const { allFeatures, isPending, isError } = useFeatures()
  const { allTasks } = useTasks()
  const { allIssues } = useIssues()
  const { mutate, isPending: isMutating } = useRecordMutation()

  const [confirming, setConfirming] = useState(false)
  const [confirmingReopen, setConfirmingReopen] = useState(false)
  const [showNote, setShowNote] = useState(false)
  const [showGitHubLink, setShowGitHubLink] = useState(false)
  const [note, setNote] = useState('')
  const [mutationError, setMutationError] = useState<string | null>(null)
  const [mutationSuccess, setMutationSuccess] = useState<string | null>(null)

  const feature = allFeatures.find((f) => f.feature_id === featureId)

  const relatedTaskIds = useMemo(() => {
    if (!feature) return []
    // Get all children IDs to exclude from related items (ENC-FTR-014 de-duplication)
    const childrenIds = getChildrenIds(feature.feature_id, allTasks)
      .concat(getChildrenIds(feature.feature_id, allIssues))
      .concat(getChildrenIds(feature.feature_id, allFeatures))

    const direct = feature.related_task_ids ?? []
    const reverse = allTasks
      .filter(
        (t) =>
          t.project_id === feature.project_id &&
          (t.related_feature_ids ?? []).includes(feature.feature_id)
      )
      .map((t) => t.task_id)
    // Filter out parent and children (de-duplication)
    const allIds = Array.from(new Set([...direct, ...reverse]))
    return filterRelatedItems(allIds, feature.parent, childrenIds)
  }, [allTasks, feature])

  const relatedIssueIds = useMemo(() => {
    if (!feature) return []
    // Get all children IDs to exclude from related items (ENC-FTR-014 de-duplication)
    const childrenIds = getChildrenIds(feature.feature_id, allTasks)
      .concat(getChildrenIds(feature.feature_id, allIssues))
      .concat(getChildrenIds(feature.feature_id, allFeatures))

    const direct = feature.related_issue_ids ?? []
    const reverse = allIssues
      .filter(
        (i) =>
          i.project_id === feature.project_id &&
          (i.related_feature_ids ?? []).includes(feature.feature_id)
      )
      .map((i) => i.issue_id)
    // Filter out parent and children (de-duplication)
    const allIds = Array.from(new Set([...direct, ...reverse]))
    return filterRelatedItems(allIds, feature.parent, childrenIds)
  }, [allIssues, allFeatures, allTasks, feature])

  // ENC-FTR-014: Compute filtered related feature IDs (de-duplicated, excludes parent/children)
  const filteredRelatedFeatureIds = useMemo(() => {
    if (!feature) return [] as string[]
    const childrenIds = getChildrenIds(feature.feature_id, allTasks)
      .concat(getChildrenIds(feature.feature_id, allIssues))
      .concat(getChildrenIds(feature.feature_id, allFeatures))
    return filterRelatedItems(feature.related_feature_ids ?? [], feature.parent, childrenIds)
  }, [feature, allTasks, allIssues, allFeatures])

  const hasRelated = relatedTaskIds.length > 0 || filteredRelatedFeatureIds.length > 0 || relatedIssueIds.length > 0

  const recordMap = useMemo<Record<string, RecordInfo>>(() => {
    const map: Record<string, RecordInfo> = {}
    for (const t of allTasks) map[t.task_id] = { title: t.title, status: t.status }
    for (const i of allIssues) map[i.issue_id] = { title: i.title, status: i.status }
    for (const f of allFeatures) map[f.feature_id] = { title: f.title, status: f.status }
    return map
  }, [allTasks, allIssues, allFeatures])

  if (isPending) return <LoadingState />
  if (isError) return <ErrorState />
  if (!feature) return <ErrorState message="Feature not found" />

  const canClose = !['completed', 'closed'].includes(feature.status)
  const canReopen = ['completed', 'closed'].includes(feature.status)

  function handleReopen() {
    setMutationError(null)
    mutate(
      { projectId: feature!.project_id, recordType: 'feature', recordId: feature!.feature_id, action: 'reopen' },
      {
        onSuccess: () => {
          setConfirmingReopen(false)
          setMutationSuccess('Feature reopened.')
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
      { projectId: feature!.project_id, recordType: 'feature', recordId: feature!.feature_id, action: 'close' },
      {
        onSuccess: () => {
          setConfirming(false)
          setMutationSuccess('Feature marked complete.')
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
      { projectId: feature!.project_id, recordType: 'feature', recordId: feature!.feature_id, action: 'note', note },
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
      <Link to="/features" className="text-xs text-blue-400 inline-block">
        &larr; Features
      </Link>

      {/* Header */}
      <div>
        <Link
          to={`/projects/${feature.project_id}`}
          className="text-xs text-blue-400 hover:text-blue-300 block mb-1"
        >
          {feature.project_id}
        </Link>
        <span className="text-xs font-mono text-slate-500 block mb-1">{feature.feature_id}</span>
        <h1 className="text-lg font-semibold text-slate-100 mb-2">{feature.title}</h1>
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <StatusChip status={feature.status} />
          {feature.category && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-violet-500/20 text-violet-400">
              {feature.category}
            </span>
          )}
          <GitHubLinkBadge url={feature.github_issue_url} />
          {feature.coordination && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-cyan-500/20 text-cyan-400" title="Part of multi-agent coordination">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-current opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-current" />
              </span>
              Coordination
            </span>
          )}
          {feature.owners.length > 0 && (
            <span className="text-xs text-slate-400">
              {feature.owners.join(', ')}
            </span>
          )}
        </div>
        <div className="flex gap-4 text-xs text-slate-500">
          <span>Created {formatDate(feature.created_at)}</span>
          <span>Updated {formatDate(feature.updated_at)}</span>
        </div>

        {/* Action bar */}
        <div className="flex items-center gap-2 mt-3">
          {canClose && !confirming && (
            <button
              onClick={() => setConfirming(true)}
              className="text-xs px-3 py-1.5 rounded-full bg-emerald-900/60 text-emerald-300 border border-emerald-700 hover:bg-emerald-800/70 transition-colors"
            >
              ✓ Complete
            </button>
          )}
          {confirming && (
            <span className="text-xs text-slate-300 flex items-center gap-2">
              Mark as completed?
              <button
                onClick={handleClose}
                disabled={isMutating}
                className="text-emerald-400 hover:text-emerald-300 disabled:opacity-50"
              >
                {isMutating ? 'Saving…' : 'Confirm'}
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
              Reopen this feature?
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
          {feature.github_issue_url ? (
            <a
              href={feature.github_issue_url}
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
      {feature.parent && (
        <ParentRecord
          parentId={feature.parent}
          allTasks={allTasks}
          allIssues={allIssues}
          allFeatures={allFeatures}
        />
      )}

      {/* Child Records */}
      <ChildRecords
        recordId={feature.feature_id}
        allTasks={allTasks}
        allIssues={allIssues}
        allFeatures={allFeatures}
      />

      {/* User Story (ENC-FTR-017 philosophy) */}
      {feature.user_story && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            User Story
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed italic">{feature.user_story}</p>
        </div>
      )}

      {/* Intent (ENC-FTR-017 philosophy) */}
      {feature.intent && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Intent
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed">{feature.intent}</p>
        </div>
      )}

      {/* Primary Task (ENC-FTR-017 philosophy) */}
      {feature.primary_task && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Primary Task
          </h3>
          <Link
            to={`/tasks/${feature.primary_task}`}
            className="text-sm text-blue-400 hover:text-blue-300 font-mono"
          >
            {feature.primary_task}
            {recordMap[feature.primary_task] && (
              <span className="text-slate-400 font-sans ml-2">
                {recordMap[feature.primary_task].title}
              </span>
            )}
          </Link>
        </div>
      )}

      {/* Description */}
      {feature.description && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Description
          </h3>
          <MarkdownRenderer content={feature.description} />
        </div>
      )}

      {/* Acceptance Criteria with Evidence (ENC-FTR-017 philosophy) */}
      {feature.acceptance_criteria && feature.acceptance_criteria.length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
            Acceptance Criteria
          </h3>
          <ul className="space-y-3">
            {feature.acceptance_criteria.map((ac, i) => (
              <li key={i} className="flex items-start gap-2.5">
                <span className={`flex-shrink-0 mt-0.5 text-sm ${ac.evidence_acceptance ? 'text-emerald-400' : 'text-slate-600'}`}>
                  {ac.evidence_acceptance ? '●' : '○'}
                </span>
                <div className="flex-1 min-w-0">
                  <p className={`text-sm ${ac.evidence_acceptance ? 'text-slate-300' : 'text-slate-400'}`}>
                    {ac.description}
                  </p>
                  {ac.evidence && (
                    <p className="text-xs text-slate-500 mt-1 pl-2 border-l border-emerald-500/30">
                      {ac.evidence}
                    </p>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Success Metrics (legacy, shown when no structured AC) */}
      {(!feature.acceptance_criteria || feature.acceptance_criteria.length === 0) && feature.success_metrics && feature.success_metrics.length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Success Metrics
          </h3>
          <ul className="space-y-1.5">
            {feature.success_metrics.map((metric, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <span className="text-emerald-400 flex-shrink-0 mt-0.5">&#x2022;</span>
                <MarkdownRenderer content={metric} className="text-slate-300 leading-relaxed inline" />
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Related Items — ENC-FTR-014: De-duplicated (excludes parent/children) */}
      <div className="bg-slate-800 rounded-lg p-4">
        <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
          Related Items
        </h3>
        {hasRelated ? (
          <RelatedItems
            groups={[
              { label: 'Tasks', ids: relatedTaskIds, routePrefix: '/tasks' },
              { label: 'Features', ids: filteredRelatedFeatureIds, routePrefix: '/features' },
              { label: 'Issues', ids: relatedIssueIds, routePrefix: '/issues' },
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
        <HistoryFeed entries={feature.history ?? []} />
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
          projectId={feature.project_id}
          recordType="feature"
          recordId={feature.feature_id}
          recordTitle={feature.title}
          recordDescription={feature.description}
          onClose={() => { setShowGitHubLink(false); setMutationError(null) }}
          onSuccess={(msg) => { setMutationSuccess(msg); setTimeout(() => setMutationSuccess(null), 4000) }}
          onError={setMutationError}
        />
      )}
    </div>
  )
}
