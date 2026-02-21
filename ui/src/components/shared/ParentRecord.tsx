import { Link } from 'react-router-dom'
import { StatusChip } from './StatusChip'
import type { Task, Issue, Feature } from '../../types/feeds'

interface ParentRecordProps {
  parentId: string
  allTasks: Task[]
  allIssues: Issue[]
  allFeatures: Feature[]
}

function routeForId(id: string): string {
  if (id.includes('-TSK-')) return `/tasks/${id}`
  if (id.includes('-ISS-')) return `/issues/${id}`
  if (id.includes('-FTR-')) return `/features/${id}`
  return '#'
}

function typeLabel(id: string): string {
  if (id.includes('-TSK-')) return 'Task'
  if (id.includes('-ISS-')) return 'Issue'
  if (id.includes('-FTR-')) return 'Feature'
  return 'Record'
}

export function ParentRecord({ parentId, allTasks, allIssues, allFeatures }: ParentRecordProps) {
  let title: string | undefined
  let status: string | undefined

  if (parentId.includes('-TSK-')) {
    const t = allTasks.find((t) => t.task_id === parentId)
    title = t?.title
    status = t?.status
  } else if (parentId.includes('-ISS-')) {
    const i = allIssues.find((i) => i.issue_id === parentId)
    title = i?.title
    status = i?.status
  } else if (parentId.includes('-FTR-')) {
    const f = allFeatures.find((f) => f.feature_id === parentId)
    title = f?.title
    status = f?.status
  }

  return (
    <div className="bg-slate-800 rounded-lg p-4">
      <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
        Parent {typeLabel(parentId)}
      </h3>
      <Link
        to={routeForId(parentId)}
        className="block rounded-md bg-slate-700/50 p-3 hover:bg-slate-700 transition-colors"
      >
        <div className="flex items-center gap-2 mb-1">
          <span className="font-mono text-xs text-blue-400">{parentId}</span>
          {status && <StatusChip status={status} />}
        </div>
        {title ? (
          <p className="text-sm text-slate-200 leading-snug">{title}</p>
        ) : (
          <p className="text-sm text-slate-500 italic">Not found in current feeds</p>
        )}
      </Link>
    </div>
  )
}
