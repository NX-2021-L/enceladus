import { COORDINATION_STATE_COLORS, COORDINATION_STATE_LABELS } from '../../lib/constants'

export function CoordinationStateBadge({ state }: { state: string }) {
  const color = COORDINATION_STATE_COLORS[state] ?? 'bg-slate-500/20 text-slate-400'
  const label = COORDINATION_STATE_LABELS[state] ?? state
  const isRunning = state === 'running' || state === 'dispatching'

  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium ${color}`}>
      {isRunning && (
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-current opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-current" />
        </span>
      )}
      {label}
    </span>
  )
}
