/**
 * PlanDetailPage — detail view for plan records (ENC-FTR-058).
 * Shows objectives set with status, attached documents, and lifecycle actions.
 */

import { useMemo, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { StatusChip } from '../components/shared/StatusChip'
import { PriorityBadge } from '../components/shared/PriorityBadge'
import { MarkdownRenderer } from '../components/shared/MarkdownRenderer'
import { HistoryFeed } from '../components/shared/HistoryFeed'
import { LifecycleActions } from '../components/shared/LifecycleActions'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { CopyButton } from '../components/shared/CopyButton'
import { formatDate } from '../lib/formatters'
import { useLiveFeed } from '../contexts/LiveFeedContext'

function getRecordPath(id: string): string {
  if (id.includes('-TSK-')) return `/tasks/${id}`
  if (id.includes('-ISS-')) return `/issues/${id}`
  if (id.includes('-FTR-')) return `/features/${id}`
  return `/tasks/${id}`
}

export function PlanDetailPage() {
  const { planId } = useParams<{ planId: string }>()
  const { plans, tasks: allTasks, issues: allIssues, features: allFeatures, isPending, isError } = useLiveFeed()

  const plan = useMemo(() => plans.find((p) => p.plan_id === planId), [plans, planId])

  // Build a lookup for objective records
  const objectivesInfo = useMemo(() => {
    if (!plan) return []
    const taskMap = new Map(allTasks.map((t) => [t.task_id, { title: t.title, status: t.status, type: 'task' }]))
    const issueMap = new Map(allIssues.map((i) => [i.issue_id, { title: i.title, status: i.status, type: 'issue' }]))
    const featureMap = new Map(allFeatures.map((f) => [f.feature_id, { title: f.title, status: f.status, type: 'feature' }]))

    return (plan.objectives_set ?? []).map((id) => {
      const info = taskMap.get(id) || issueMap.get(id) || featureMap.get(id)
      return { id, title: info?.title ?? id, status: info?.status ?? 'unknown', type: info?.type ?? 'unknown' }
    })
  }, [plan, allTasks, allIssues, allFeatures])

  const closedCount = objectivesInfo.filter((o) =>
    ['closed', 'completed', 'complete', 'production'].includes(o.status)
  ).length

  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  if (isPending) return <LoadingState />
  if (isError) return <ErrorState message="Failed to load plan data" />
  if (!plan) return <ErrorState message={`Plan ${planId} not found`} />

  return (
    <div className="space-y-4 pb-24">
      {/* Header */}
      <div className="bg-slate-800 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-2">
          <span className="font-mono text-xs text-indigo-400">{plan.plan_id}</span>
          <CopyButton text={plan.plan_id} />
        </div>
        <h1 className="text-lg font-semibold text-slate-100 mb-2">{plan.title}</h1>
        <div className="flex flex-wrap items-center gap-2">
          <StatusChip status={plan.status} />
          <PriorityBadge priority={plan.priority} />
          {plan.category && (
            <span className="text-xs text-slate-500 bg-slate-700/50 px-2 py-0.5 rounded">{plan.category}</span>
          )}
          {plan.checkout_state && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/20 text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Checked out by {plan.checked_out_by}
            </span>
          )}
          {plan.related_feature_id && (
            <Link to={`/features/${plan.related_feature_id}`} className="text-xs text-blue-400 font-mono hover:underline">
              {plan.related_feature_id}
            </Link>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2 mt-3">
          <LifecycleActions
            recordType="plan"
            currentStatus={plan.status}
            projectId={plan.project_id}
            recordId={plan.plan_id}
            onSuccess={(msg) => { setToast({ type: 'success', message: msg }); setTimeout(() => setToast(null), 4000) }}
            onError={(msg) => { setToast({ type: 'error', message: msg }); setTimeout(() => setToast(null), 8000) }}
          />
        </div>
        <div className="text-xs text-slate-500 mt-2">
          Created {formatDate(plan.created_at)} · Updated {formatDate(plan.updated_at)}
        </div>
      </div>

      {/* Toast feedback */}
      {toast && (
        <div className={`rounded-lg p-3 text-sm ${toast.type === 'success' ? 'bg-emerald-900/60 text-emerald-300 border border-emerald-700' : 'bg-red-900/60 text-red-300 border border-red-700'}`}>
          {toast.message}
        </div>
      )}

      {/* Description */}
      {plan.description && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">Description</h3>
          <MarkdownRenderer content={plan.description} />
        </div>
      )}

      {/* Objectives Set */}
      <div className="bg-slate-800 rounded-lg p-4">
        <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
          Objectives ({closedCount}/{objectivesInfo.length} complete)
        </h3>
        {objectivesInfo.length > 0 ? (
          <>
            {/* Progress bar */}
            <div className="w-full h-1.5 bg-slate-700 rounded-full mb-3">
              <div
                className="h-full bg-emerald-500 rounded-full transition-all"
                style={{ width: `${objectivesInfo.length > 0 ? (closedCount / objectivesInfo.length) * 100 : 0}%` }}
              />
            </div>
            <div className="space-y-1.5">
              {objectivesInfo.map((obj) => (
                <Link
                  key={obj.id}
                  to={getRecordPath(obj.id)}
                  className="flex items-center gap-2 rounded-md bg-slate-700/50 p-2 hover:bg-slate-700 transition-colors"
                >
                  <span className="font-mono text-[10px] text-blue-400 flex-shrink-0">{obj.id}</span>
                  <StatusChip status={obj.status} />
                  <span className="text-sm text-slate-300 truncate">{obj.title}</span>
                </Link>
              ))}
            </div>
          </>
        ) : (
          <p className="text-sm text-slate-500">No objectives set.</p>
        )}
      </div>

      {/* Attached Documents */}
      {plan.attached_documents && plan.attached_documents.length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
            Attached Documents ({plan.attached_documents.length})
          </h3>
          <div className="space-y-1.5">
            {plan.attached_documents.map((docId) => (
              <Link
                key={docId}
                to={`/documents/${docId}`}
                className="flex items-center gap-2 rounded-md bg-slate-700/50 p-2 hover:bg-slate-700 transition-colors"
              >
                <span className="font-mono text-xs text-cyan-400">{docId}</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* History */}
      <div className="bg-slate-800 rounded-lg p-4">
        <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">History</h3>
        <HistoryFeed entries={plan.history ?? []} />
      </div>
    </div>
  )
}
