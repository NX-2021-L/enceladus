import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useCoordinationDetail } from '../hooks/useCoordination'
import { CoordinationStateBadge } from '../components/shared/CoordinationStateBadge'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { formatDate, timeAgo } from '../lib/formatters'
import type { CoordinationStateHistoryEntry } from '../types/coordination'

function routeForRecordId(id: string): string {
  if (id.includes('-TSK-')) return `/tasks/${id}`
  if (id.includes('-ISS-')) return `/issues/${id}`
  if (id.includes('-FTR-')) return `/features/${id}`
  return `/feed`
}

function StateTimeline({ entries }: { entries: CoordinationStateHistoryEntry[] }) {
  if (!entries.length) {
    return <p className="text-sm text-slate-500">No state transitions recorded.</p>
  }

  return (
    <div className="space-y-2">
      {entries.map((entry, i) => (
        <div key={i} className="flex items-start gap-3">
          <div className="flex-shrink-0 mt-1">
            <div className="w-2 h-2 rounded-full bg-purple-400" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 text-xs">
              <span className="text-slate-500 font-mono">{formatDate(entry.timestamp)}</span>
              <span className="text-slate-600">{entry.from}</span>
              <span className="text-slate-600">&rarr;</span>
              <CoordinationStateBadge state={entry.to} />
            </div>
            {entry.description && (
              <p className="text-xs text-slate-400 mt-0.5">{entry.description}</p>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

export function CoordinationDetailPage() {
  const { requestId } = useParams<{ requestId: string }>()
  const { request, isPending, isError } = useCoordinationDetail(requestId)
  const [mcpExpanded, setMcpExpanded] = useState(false)

  if (isPending) return <LoadingState />
  if (isError) return <ErrorState />
  if (!request) return <ErrorState message="Coordination request not found" />

  const isTerminal = ['succeeded', 'failed', 'cancelled', 'dead_letter'].includes(request.state)

  return (
    <div className="p-4 space-y-4 pb-24">
      {/* Back link */}
      <Link to="/coordination" className="text-xs text-purple-400 inline-block">
        &larr; Coordination Monitor
      </Link>

      {/* Header */}
      <div>
        <Link
          to={`/projects/${request.project_id}`}
          className="text-xs text-blue-400 hover:text-blue-300 block mb-1"
        >
          {request.project_id}
        </Link>
        <span className="text-xs font-mono text-slate-500 block mb-1">{request.request_id}</span>
        <h1 className="text-lg font-semibold text-slate-100 mb-2">{request.initiative_title}</h1>
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <CoordinationStateBadge state={request.state} />
          {request.execution_mode && (
            <span className="text-xs text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded">
              {request.execution_mode.replace(/_/g, ' ')}
            </span>
          )}
          {request.dispatch_attempts != null && request.dispatch_attempts > 0 && (
            <span className="text-xs text-slate-500">
              {request.dispatch_attempts} dispatch attempt{request.dispatch_attempts !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div className="flex gap-4 text-xs text-slate-500">
          <span>Created {formatDate(request.created_at)}</span>
          <span>Updated {timeAgo(request.updated_at)}</span>
        </div>
      </div>

      {/* Result (terminal states) */}
      {isTerminal && request.result && (
        <div className={`rounded-lg p-4 ${
          request.state === 'succeeded' ? 'bg-emerald-900/30 border border-emerald-800' : 'bg-red-900/30 border border-red-800'
        }`}>
          <h3 className="text-xs font-medium uppercase tracking-wider mb-2 text-slate-400">
            Result
          </h3>
          {request.result.summary && (
            <p className="text-sm text-slate-200">{request.result.summary}</p>
          )}
          {request.result.failure_class && (
            <p className="text-xs text-red-400 mt-1 font-mono">
              failure_class: {request.result.failure_class}
            </p>
          )}
        </div>
      )}

      {/* Outcomes */}
      {request.outcomes.length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Outcomes ({request.outcomes.length})
          </h3>
          <ul className="space-y-1.5">
            {request.outcomes.map((outcome, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <span className="flex-shrink-0 mt-0.5 text-purple-400">&#x2022;</span>
                <span className="text-slate-300">{outcome}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Dispatch Plan */}
      {request.dispatch_plan && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Dispatch Plan
          </h3>
          <div className="space-y-2 text-sm">
            <div className="flex gap-2">
              <span className="text-slate-500">Plan ID:</span>
              <span className="text-slate-300 font-mono text-xs">{request.dispatch_plan.plan_id}</span>
            </div>
            <div className="flex gap-2">
              <span className="text-slate-500">Dispatches:</span>
              <span className="text-slate-300">{request.dispatch_plan.dispatches_count}</span>
            </div>
            {request.dispatch_plan.strategy && (
              <>
                <div className="flex gap-2">
                  <span className="text-slate-500">Decomposition:</span>
                  <span className="text-slate-300">{request.dispatch_plan.strategy.decomposition}</span>
                </div>
                {request.dispatch_plan.strategy.estimated_duration_minutes && (
                  <div className="flex gap-2">
                    <span className="text-slate-500">Est. Duration:</span>
                    <span className="text-slate-300">
                      {request.dispatch_plan.strategy.estimated_duration_minutes} min
                    </span>
                  </div>
                )}
                {request.dispatch_plan.strategy.rationale && (
                  <div>
                    <span className="text-slate-500 block mb-1">Rationale:</span>
                    <p className="text-slate-300 text-xs bg-slate-900/50 rounded p-2">
                      {request.dispatch_plan.strategy.rationale}
                    </p>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}

      {/* Constraints */}
      {request.constraints && Object.keys(request.constraints).length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Constraints
          </h3>
          <pre className="text-xs text-slate-300 overflow-x-auto">
            {JSON.stringify(request.constraints, null, 2)}
          </pre>
        </div>
      )}

      {/* Related Record IDs */}
      {request.related_record_ids && request.related_record_ids.length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Related Records ({request.related_record_ids.length})
          </h3>
          <div className="flex flex-wrap gap-2">
            {request.related_record_ids.map((id) => (
              <Link
                key={id}
                to={routeForRecordId(id)}
                className="text-xs font-mono text-blue-400 hover:text-blue-300 bg-blue-500/10 px-2 py-1 rounded"
              >
                {id}
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* State History */}
      <div className="bg-slate-800 rounded-lg p-4">
        <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
          State History ({request.state_history?.length ?? 0})
        </h3>
        <StateTimeline entries={request.state_history ?? []} />
      </div>

      {/* Provider Preferences */}
      {request.provider_preferences && Object.keys(request.provider_preferences).length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
            Provider Preferences
          </h3>
          <pre className="text-xs text-slate-300 overflow-x-auto">
            {JSON.stringify(request.provider_preferences, null, 2)}
          </pre>
        </div>
      )}

      {/* MCP Diagnostic Data (collapsible) */}
      {request.mcp && Object.keys(request.mcp).length > 0 && (
        <div className="bg-slate-800 rounded-lg p-4">
          <button
            onClick={() => setMcpExpanded((prev) => !prev)}
            className="text-xs font-medium text-slate-400 uppercase tracking-wider flex items-center gap-2 w-full"
          >
            <span className={`transform transition-transform ${mcpExpanded ? 'rotate-90' : ''}`}>
              &#x25B6;
            </span>
            MCP Diagnostics
          </button>
          {mcpExpanded && (
            <pre className="text-xs text-slate-400 overflow-x-auto mt-2 max-h-96 overflow-y-auto">
              {JSON.stringify(request.mcp, null, 2)}
            </pre>
          )}
        </div>
      )}

      {/* Metadata footer */}
      <div className="text-xs text-slate-600 space-y-1">
        {request.requestor_session_id && (
          <p>Session: {request.requestor_session_id}</p>
        )}
      </div>
    </div>
  )
}
