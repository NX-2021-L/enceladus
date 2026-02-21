import { Link } from 'react-router-dom'
import type { Feature } from '../../types/feeds'
import { StatusChip } from '../shared/StatusChip'
import { timeAgo } from '../../lib/formatters'

export function FeatureRow({ feature }: { feature: Feature }) {
  return (
    <Link
      to={`/features/${feature.feature_id}`}
      className="block bg-slate-800 rounded-lg px-4 py-3 hover:bg-slate-750 active:bg-slate-700 transition-colors"
    >
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-xs font-mono text-slate-500 flex-shrink-0">{feature.feature_id}</span>
            <span className="text-xs text-slate-600">{feature.project_id}</span>
          </div>
          <h4 className="text-sm font-medium text-slate-200 truncate">{feature.title}</h4>
        </div>
        <span className="text-xs text-slate-500 flex-shrink-0">{timeAgo(feature.updated_at)}</span>
      </div>
      <div className="flex items-center gap-2 mt-1.5">
        <StatusChip status={feature.status} />
        {feature.success_metrics_count > 0 && (
          <span className="text-xs text-slate-500">{feature.success_metrics_count} metrics</span>
        )}
      </div>
    </Link>
  )
}
