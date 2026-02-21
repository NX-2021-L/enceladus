import { Link } from 'react-router-dom'
import type { Issue } from '../../types/feeds'
import { StatusChip } from '../shared/StatusChip'
import { PriorityBadge } from '../shared/PriorityBadge'
import { SeverityBadge } from '../shared/SeverityBadge'
import { timeAgo } from '../../lib/formatters'

export function IssueRow({ issue }: { issue: Issue }) {
  return (
    <Link
      to={`/issues/${issue.issue_id}`}
      className="block bg-slate-800 rounded-lg px-4 py-3 hover:bg-slate-750 active:bg-slate-700 transition-colors"
    >
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-xs font-mono text-slate-500 flex-shrink-0">{issue.issue_id}</span>
            <span className="text-xs text-slate-600">{issue.project_id}</span>
          </div>
          <h4 className="text-sm font-medium text-slate-200 truncate">{issue.title}</h4>
        </div>
        <span className="text-xs text-slate-500 flex-shrink-0">{timeAgo(issue.updated_at)}</span>
      </div>
      <div className="flex items-center gap-2 mt-1.5">
        <StatusChip status={issue.status} />
        <PriorityBadge priority={issue.priority} />
        <SeverityBadge severity={issue.severity} />
      </div>
    </Link>
  )
}
