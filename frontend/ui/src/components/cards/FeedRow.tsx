import type { FeedItem } from '../../types/feed'
import { TaskRow } from './TaskRow'
import { IssueRow } from './IssueRow'
import { FeatureRow } from './FeatureRow'
import { LessonRow } from './LessonRow'

const BORDER_COLOR: Record<string, string> = {
  task: 'border-l-blue-400',
  issue: 'border-l-amber-400',
  feature: 'border-l-emerald-400',
  lesson: 'border-l-purple-400',
}

export function FeedRow({ item }: { item: FeedItem }) {
  return (
    <div className={`border-l-2 ${BORDER_COLOR[item._type] ?? 'border-l-slate-400'} rounded-l-sm`}>
      {item._type === 'task' && <TaskRow task={item.data} />}
      {item._type === 'issue' && <IssueRow issue={item.data} />}
      {item._type === 'feature' && <FeatureRow feature={item.data} />}
      {item._type === 'lesson' && <LessonRow lesson={item.data} />}
    </div>
  )
}
