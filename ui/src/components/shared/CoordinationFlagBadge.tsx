export function CoordinationFlagBadge({ isCoordination }: { isCoordination: boolean }) {
  if (!isCoordination) return null

  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-cyan-500/20 text-cyan-400" title="Part of multi-agent coordination">
      <span className="relative flex h-2 w-2">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-current opacity-75" />
        <span className="relative inline-flex rounded-full h-2 w-2 bg-current" />
      </span>
      Coordination
    </span>
  )
}
