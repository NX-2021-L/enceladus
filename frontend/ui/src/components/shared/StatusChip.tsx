import { STATUS_COLORS, STATUS_LABELS } from '../../lib/constants'

export function StatusChip({ status }: { status: string }) {
  const color = STATUS_COLORS[status] ?? STATUS_COLORS.open
  const label = STATUS_LABELS[status] ?? status
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${color}`}>
      {label}
    </span>
  )
}
