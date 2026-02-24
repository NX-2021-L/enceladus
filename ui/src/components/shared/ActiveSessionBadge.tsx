export function ActiveSessionBadge({ isActive, agentSessionId }: { isActive: boolean; agentSessionId?: string }) {
  if (!isActive) return null

  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/20 text-emerald-400" title={agentSessionId ? `Active: ${agentSessionId}` : 'Active'}>
      <span className="relative flex h-2 w-2">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-current opacity-75" />
        <span className="relative inline-flex rounded-full h-2 w-2 bg-current" />
      </span>
      Active
    </span>
  )
}
