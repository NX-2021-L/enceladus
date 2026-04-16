/**
 * DeploymentManagerPage — GMF Production Governance Surface (DOC-63420302EF65 §6).
 *
 * The primary governance surface through which io exercises production authority.
 * Displays pending deployment decisions with approve/divert/revert actions,
 * and a deployment history timeline.
 */

import { useState, useCallback } from 'react'
import { useDeployQueue, useDeployDecision, timeInQueue } from '../hooks/useDeploymentManager'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { EmptyState } from '../components/shared/EmptyState'
import type { DeploymentDecision } from '../types/deployments'

// ---------------------------------------------------------------------------
// Status badge colors
// ---------------------------------------------------------------------------

const STATUS_COLORS: Record<string, string> = {
  pending_approval: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  approved: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  diverted: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  reverted: 'bg-red-500/20 text-red-400 border-red-500/30',
  deploying: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  deployed: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  failed: 'bg-red-500/20 text-red-400 border-red-500/30',
}

const TARGET_COLORS: Record<string, string> = {
  prod: 'bg-red-500/20 text-red-300',
  gamma: 'bg-blue-500/20 text-blue-300',
  undeclared: 'bg-slate-500/20 text-slate-400',
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${
        STATUS_COLORS[status] || 'bg-slate-700 text-slate-300 border-slate-600'
      }`}
    >
      {status.replace(/_/g, ' ')}
    </span>
  )
}

function TargetBadge({ target }: { target: string }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium ${
        TARGET_COLORS[target] || 'bg-slate-700 text-slate-400'
      }`}
    >
      {target}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Decision Card
// ---------------------------------------------------------------------------

function DecisionCard({
  decision,
  onAction,
  isActing,
}: {
  decision: DeploymentDecision
  onAction: (action: 'approve' | 'divert' | 'revert', prNumber: number, reason?: string) => void
  isActing: boolean
}) {
  const [showRevertDialog, setShowRevertDialog] = useState(false)
  const [revertReason, setRevertReason] = useState('')

  const isPending = decision.status === 'pending_approval'
  const queue_time = timeInQueue(decision.created_at)

  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4 space-y-3">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1">
            <a
              href={decision.github_pr_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm font-semibold text-slate-100 hover:text-blue-400 transition-colors truncate"
            >
              #{decision.github_pr_number} {decision.pr_title}
            </a>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>{decision.pr_author}</span>
            <span className="text-slate-600">&middot;</span>
            <span className="font-mono">{decision.head_branch}</span>
            <span className="text-slate-600">&middot;</span>
            <span>{queue_time} in queue</span>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <TargetBadge target={decision.original_target} />
          <StatusBadge status={decision.status} />
        </div>
      </div>

      {/* SHA */}
      <div className="flex items-center gap-2 text-xs">
        <span className="text-slate-500">SHA:</span>
        <code className="text-slate-400 font-mono">{decision.head_sha.slice(0, 12)}</code>
      </div>

      {/* Linked records */}
      {(decision.related_enceladus_task_ids?.length > 0 ||
        decision.related_enceladus_feature_ids?.length > 0) && (
        <div className="flex flex-wrap gap-1">
          {decision.related_enceladus_task_ids?.map((id) => (
            <span
              key={id}
              className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-slate-700/50 text-slate-300 font-mono"
            >
              {id}
            </span>
          ))}
          {decision.related_enceladus_feature_ids?.map((id) => (
            <span
              key={id}
              className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-purple-500/10 text-purple-300 font-mono"
            >
              {id}
            </span>
          ))}
        </div>
      )}

      {/* Decision outcome for non-pending */}
      {!isPending && decision.decided_by && (
        <div className="text-xs text-slate-400 border-t border-slate-700/50 pt-2">
          {decision.status === 'approved' && 'Approved'}
          {decision.status === 'diverted' && 'Diverted to gamma'}
          {decision.status === 'reverted' && 'Reverted'}
          {decision.status === 'deployed' && 'Deployed'}
          {decision.status === 'failed' && 'Deploy failed'}
          {' by '}
          <span className="text-slate-300">{decision.decided_by}</span>
          {decision.decided_at && (
            <>
              {' at '}
              <span className="text-slate-300">
                {new Date(decision.decided_at).toLocaleString()}
              </span>
            </>
          )}
          {decision.decision_reason && (
            <div className="mt-1 text-slate-500 italic">
              &ldquo;{decision.decision_reason}&rdquo;
            </div>
          )}
          {/* ENC-TSK-E57: Show approval token for approved decisions */}
          {decision.approval_token && (
            <div className="mt-1">
              <span className="text-slate-500">Token: </span>
              <code className="text-emerald-400 font-mono text-xs select-all">
                {decision.approval_token}
              </code>
            </div>
          )}
        </div>
      )}

      {/* ENC-TSK-E57: Bypass marker for pre-E57 deploys */}
      {decision.bypass_reason && (
        <div className="flex items-center gap-1 text-xs">
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-amber-500/20 text-amber-400 border border-amber-500/30">
            bypass
          </span>
          <span className="text-slate-500">{decision.bypass_reason}</span>
        </div>
      )}

      {/* Action buttons (only for pending_approval) */}
      {isPending && (
        <>
          {!showRevertDialog ? (
            <div className="flex gap-2 pt-1">
              <button
                onClick={() => onAction('approve', decision.github_pr_number)}
                disabled={isActing}
                className="flex-1 px-3 py-2 rounded-lg text-sm font-medium bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Approve &rarr; Prod
              </button>
              <button
                onClick={() => onAction('divert', decision.github_pr_number)}
                disabled={isActing}
                className="flex-1 px-3 py-2 rounded-lg text-sm font-medium bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Divert &rarr; Gamma
              </button>
              <button
                onClick={() => setShowRevertDialog(true)}
                disabled={isActing}
                className="px-3 py-2 rounded-lg text-sm font-medium bg-red-600/20 hover:bg-red-600/40 active:bg-red-600/60 text-red-400 border border-red-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Revert
              </button>
            </div>
          ) : (
            <div className="space-y-2 pt-1 border-t border-red-500/20">
              <p className="text-xs text-red-400 font-medium">
                Revert will close this PR without merging. A reason is required.
              </p>
              <textarea
                value={revertReason}
                onChange={(e) => setRevertReason(e.target.value)}
                placeholder="Why is this PR being reverted?"
                rows={2}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-red-500/50"
              />
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    onAction('revert', decision.github_pr_number, revertReason)
                    setShowRevertDialog(false)
                    setRevertReason('')
                  }}
                  disabled={isActing || !revertReason.trim()}
                  className="flex-1 px-3 py-2 rounded-lg text-sm font-medium bg-red-600 hover:bg-red-500 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  Confirm Revert
                </button>
                <button
                  onClick={() => {
                    setShowRevertDialog(false)
                    setRevertReason('')
                  }}
                  className="px-3 py-2 rounded-lg text-sm font-medium bg-slate-700 hover:bg-slate-600 text-slate-300 transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

export function DeploymentManagerPage() {
  const { decisions, count, isPending, isError, refetch } = useDeployQueue()
  const decideMutation = useDeployDecision()
  const [actionError, setActionError] = useState<string | null>(null)

  const pendingDecisions = decisions.filter((d) => d.status === 'pending_approval')

  const handleAction = useCallback(
    async (action: 'approve' | 'divert' | 'revert', prNumber: number, reason?: string) => {
      setActionError(null)
      try {
        await decideMutation.mutateAsync({
          action,
          pr_number: prNumber,
          decision_reason: reason,
        })
      } catch (err) {
        setActionError(err instanceof Error ? err.message : 'Decision failed')
        // Auto-dismiss after 6 seconds
        setTimeout(() => setActionError(null), 6000)
      }
    },
    [decideMutation],
  )

  if (isPending) return <LoadingState />
  if (isError) return <ErrorState />

  return (
    <div className="p-4 space-y-6 max-w-2xl mx-auto">
      {/* Page header */}
      <div>
        <h2 className="text-lg font-semibold text-slate-100">Deployment Manager</h2>
        <p className="text-xs text-slate-500 mt-1">
          Production governance surface &mdash; approve, divert, or revert pending deployments
        </p>
      </div>

      {/* Error toast */}
      {actionError && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">
          {actionError}
        </div>
      )}

      {/* Pending Approvals Section */}
      <section>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-slate-300">
            Pending Approvals
            {count > 0 && (
              <span className="ml-2 inline-flex items-center justify-center w-5 h-5 rounded-full bg-amber-500/20 text-amber-400 text-xs font-bold">
                {count}
              </span>
            )}
          </h3>
          <button
            onClick={() => refetch()}
            className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
          >
            Refresh
          </button>
        </div>

        {pendingDecisions.length > 0 ? (
          <div className="space-y-3">
            {pendingDecisions.map((d) => (
              <DecisionCard
                key={d.record_id}
                decision={d}
                onAction={handleAction}
                isActing={decideMutation.isPending}
              />
            ))}
          </div>
        ) : (
          <EmptyState message="No deployments pending approval" />
        )}
      </section>

      {/* Deployment Queue Info */}
      <section className="border-t border-slate-700/50 pt-4">
        <p className="text-xs text-slate-500">
          Polling every 5s &middot; {count} total in queue &middot; Cognito-authenticated actions
        </p>
      </section>
    </div>
  )
}
