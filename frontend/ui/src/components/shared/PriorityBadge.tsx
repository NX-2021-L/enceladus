import { PRIORITY_COLORS } from '../../lib/constants'

export function PriorityBadge({ priority }: { priority: string }) {
  const color = PRIORITY_COLORS[priority] ?? PRIORITY_COLORS.P3
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${color}`}>
      {priority}
    </span>
  )
}
