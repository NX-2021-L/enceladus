import { Link } from 'react-router-dom'
import { CoordinationStateBadge } from '../shared/CoordinationStateBadge'
import { timeAgo } from '../../lib/formatters'
import type { CoordinationRequest } from '../../types/coordination'

export function CoordinationRow({ request }: { request: CoordinationRequest }) {
  return (
    <Link
      to={`/coordination/${request.request_id}`}
      className="block bg-slate-800 rounded-lg p-3 border-l-4 border-l-purple-400 hover:bg-slate-750 active:bg-slate-700 transition-colors"
    >
      <div className="flex items-start justify-between gap-2 mb-1">
        <span className="text-xs font-mono text-slate-500">{request.request_id}</span>
        <span className="text-xs text-slate-500 flex-shrink-0">
          {timeAgo(request.updated_at)}
        </span>
      </div>

      <h3 className="text-sm font-medium text-slate-100 mb-2 line-clamp-2">
        {request.initiative_title}
      </h3>

      <div className="flex flex-wrap items-center gap-2">
        <CoordinationStateBadge state={request.state} />

        <span className="text-xs text-slate-500">{request.project_id}</span>

        {request.execution_mode && (
          <span className="text-xs text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded">
            {request.execution_mode.replace(/_/g, ' ')}
          </span>
        )}

        {request.outcomes.length > 0 && (
          <span className="text-xs text-slate-500">
            {request.outcomes.length} outcome{request.outcomes.length !== 1 ? 's' : ''}
          </span>
        )}

        {request.dispatch_plan && (
          <span className="text-xs text-slate-500">
            {request.dispatch_plan.dispatches_count} dispatch{request.dispatch_plan.dispatches_count !== 1 ? 'es' : ''}
          </span>
        )}
      </div>
    </Link>
  )
}
