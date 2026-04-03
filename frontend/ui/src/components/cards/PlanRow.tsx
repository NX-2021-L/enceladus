/**
 * PlanRow — feed card for plan records (ENC-FTR-058).
 * Shows plan title, status, objectives progress, and feature link.
 */

import { Link } from 'react-router-dom'
import { StatusChip } from '../shared/StatusChip'
import { PriorityBadge } from '../shared/PriorityBadge'
import type { Plan } from '../../types/feeds'

export function PlanRow({ plan }: { plan: Plan }) {
  const totalObjectives = plan.objectives_set?.length ?? 0

  return (
    <Link
      to={`/plans/${plan.plan_id}`}
      className="block bg-slate-800 rounded-lg px-4 py-3 hover:bg-slate-750 active:bg-slate-700 transition-colors border-l-2 border-l-indigo-400"
    >
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-xs font-mono text-indigo-400 flex-shrink-0">{plan.plan_id}</span>
          <StatusChip status={plan.status} />
          <PriorityBadge priority={plan.priority} />
          {plan.checkout_state && (
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-500/20 text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              checked out
            </span>
          )}
        </div>
        <span className="text-xs text-slate-500 flex-shrink-0">
          {plan.updated_at ? new Date(plan.updated_at).toLocaleDateString() : ''}
        </span>
      </div>
      <p className="text-sm text-slate-200 truncate">{plan.title}</p>
      {totalObjectives > 0 && (
        <div className="mt-1.5 flex items-center gap-2">
          <span className="text-[10px] text-slate-500">
            {totalObjectives} objective{totalObjectives !== 1 ? 's' : ''}
          </span>
          {plan.related_feature_id && (
            <span className="text-[10px] text-blue-400 font-mono">{plan.related_feature_id}</span>
          )}
        </div>
      )}
    </Link>
  )
}
