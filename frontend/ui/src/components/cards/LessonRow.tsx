import { Link } from 'react-router-dom'
import type { Lesson } from '../../types/feeds'
import { StatusChip } from '../shared/StatusChip'
import { timeAgo } from '../../lib/formatters'

export function LessonRow({ lesson }: { lesson: Lesson }) {
  const composite = typeof lesson.pillar_composite === 'number'
    ? lesson.pillar_composite.toFixed(2)
    : null

  return (
    <Link
      to={`/lessons/${lesson.lesson_id}`}
      className="block bg-slate-800 rounded-lg px-4 py-3 hover:bg-slate-750 active:bg-slate-700 transition-colors"
    >
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-xs font-mono text-slate-500 flex-shrink-0">{lesson.lesson_id}</span>
            <span className="text-xs text-slate-600">{lesson.project_id}</span>
          </div>
          <h4 className="text-sm font-medium text-slate-200 truncate">{lesson.title}</h4>
        </div>
        <span className="text-xs text-slate-500 flex-shrink-0">{timeAgo(lesson.updated_at)}</span>
      </div>
      <div className="flex items-center gap-2 mt-1.5 flex-wrap">
        <StatusChip status={lesson.status} />
        {lesson.category && (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-500/20 text-purple-400">
            {lesson.category}
          </span>
        )}
        {lesson.provenance && (
          <span className="text-xs text-slate-500">{lesson.provenance}</span>
        )}
        {composite && (
          <span className="text-xs font-mono text-purple-300" title="Pillar Composite Score">
            {composite}
          </span>
        )}
        {typeof lesson.confidence === 'number' && lesson.confidence > 0 && (
          <span className="text-xs text-slate-500" title="Confidence">
            conf: {(lesson.confidence * 100).toFixed(0)}%
          </span>
        )}
      </div>
    </Link>
  )
}
