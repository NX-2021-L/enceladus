import type { FeedItem } from '../../types/feed'
import { TaskRow } from './TaskRow'
import { IssueRow } from './IssueRow'
import { FeatureRow } from './FeatureRow'

const BORDER_COLOR: Record<string, string> = {
  task: 'border-l-blue-400',
  issue: 'border-l-amber-400',
  feature: 'border-l-emerald-400',
}

export function FeedRow({ item }: { item: FeedItem }) {
  return (
    <div className={`border-l-2 ${BORDER_COLOR[item._type]} rounded-l-sm`}>
      {item._type === 'task' && <TaskRow task={item.data} />}
      {item._type === 'issue' && <IssueRow issue={item.data} />}
      {item._type === 'feature' && <FeatureRow feature={item.data} />}
    </div>
  )
}
