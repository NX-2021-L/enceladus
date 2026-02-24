import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { StatusChip } from './StatusChip'
import type { Task, Issue, Feature } from '../../types/feeds'

interface ChildRecordsProps {
  recordId: string
  allTasks: Task[]
  allIssues: Issue[]
  allFeatures: Feature[]
}

interface ChildItem {
  id: string
  title: string
  status: string
  route: string
}

export function ChildRecords({ recordId, allTasks, allIssues, allFeatures }: ChildRecordsProps) {
  const groups = useMemo(() => {
    const childTasks: ChildItem[] = allTasks
      .filter((t) => t.parent === recordId)
      .map((t) => ({ id: t.task_id, title: t.title, status: t.status, route: `/tasks/${t.task_id}` }))

    const childIssues: ChildItem[] = allIssues
      .filter((i) => i.parent === recordId)
      .map((i) => ({ id: i.issue_id, title: i.title, status: i.status, route: `/issues/${i.issue_id}` }))

    const childFeatures: ChildItem[] = allFeatures
      .filter((f) => f.parent === recordId)
      .map((f) => ({ id: f.feature_id, title: f.title, status: f.status, route: `/features/${f.feature_id}` }))

    const result: { label: string; items: ChildItem[] }[] = []
    if (childTasks.length) result.push({ label: 'Tasks', items: childTasks })
    if (childIssues.length) result.push({ label: 'Issues', items: childIssues })
    if (childFeatures.length) result.push({ label: 'Features', items: childFeatures })
    return result
  }, [recordId, allTasks, allIssues, allFeatures])

  if (groups.length === 0) return null

  const total = groups.reduce((sum, g) => sum + g.items.length, 0)

  return (
    <div className="bg-slate-800 rounded-lg p-4">
      <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
        Child Records ({total})
      </h3>
      <div className="space-y-3">
        {groups.map((group) => (
          <div key={group.label}>
            <h4 className="text-xs font-medium text-slate-500 mb-2">{group.label}</h4>
            <div className="space-y-1.5">
              {group.items.map((child) => (
                <Link
                  key={child.id}
                  to={child.route}
                  className="flex items-start gap-2 rounded-md bg-slate-700/50 p-2.5 hover:bg-slate-700 transition-colors"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="font-mono text-xs text-blue-400 flex-shrink-0">{child.id}</span>
                      <StatusChip status={child.status} />
                    </div>
                    <p className="text-sm text-slate-300 truncate">{child.title}</p>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
