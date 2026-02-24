import { Link } from 'react-router-dom'
import type { Task } from '../../types/feeds'
import { StatusChip } from '../shared/StatusChip'
import { PriorityBadge } from '../shared/PriorityBadge'
import { ActiveSessionBadge } from '../shared/ActiveSessionBadge'
import { CoordinationFlagBadge } from '../shared/CoordinationFlagBadge'
import { timeAgo } from '../../lib/formatters'

export function TaskRow({ task }: { task: Task }) {
  return (
    <Link
      to={`/tasks/${task.task_id}`}
      className="block bg-slate-800 rounded-lg px-4 py-3 hover:bg-slate-750 active:bg-slate-700 transition-colors"
    >
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-xs font-mono text-slate-500 flex-shrink-0">{task.task_id}</span>
            <span className="text-xs text-slate-600">{task.project_id}</span>
          </div>
          <h4 className="text-sm font-medium text-slate-200 truncate">{task.title}</h4>
        </div>
        <span className="text-xs text-slate-500 flex-shrink-0">{timeAgo(task.updated_at)}</span>
      </div>
      <div className="flex items-center gap-2 mt-1.5 flex-wrap">
        <StatusChip status={task.status} />
        <PriorityBadge priority={task.priority} />
        {task.active_agent_session && <ActiveSessionBadge isActive agentSessionId={task.active_agent_session_id} />}
        {task.coordination && <CoordinationFlagBadge isCoordination />}
        {task.checklist_total > 0 && (
          <span className="text-xs text-slate-500">
            {task.checklist_done}/{task.checklist_total}
          </span>
        )}
        {task.parent && (
          <span className="text-xs text-blue-400 truncate" title={`Parent: ${task.parent}`}>
            Parent: {task.parent}
          </span>
        )}
      </div>
    </Link>
  )
}
