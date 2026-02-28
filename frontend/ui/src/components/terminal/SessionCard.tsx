import { useState } from 'react'
import type { TerminalSession } from '../../types/terminal'
import { CoordinationStateBadge } from '../shared/CoordinationStateBadge'

interface SessionCardProps {
  session: TerminalSession
  onResume: (session: TerminalSession) => void
  onEnd: (session: TerminalSession) => void
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

export function SessionCard({ session, onResume, onEnd }: SessionCardProps) {
  const [hovered, setHovered] = useState(false)

  return (
    <div
      className="relative bg-slate-800 border border-slate-700/50 rounded-lg p-4 transition-colors hover:border-slate-600"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onTouchStart={() => setHovered(true)}
      onTouchEnd={() => setTimeout(() => setHovered(false), 2000)}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className={`w-2 h-2 rounded-full shrink-0 ${session.is_active ? 'bg-emerald-400' : 'bg-slate-500'}`} />
          <span className="text-sm font-mono text-slate-300 truncate">{session.session_id.slice(0, 12)}</span>
        </div>
        <CoordinationStateBadge state={session.latest_state} />
      </div>

      <div className="flex items-center gap-3 text-xs text-slate-500">
        <span>{session.provider}</span>
        <span>&middot;</span>
        <span>{session.turn_count} turn{session.turn_count !== 1 ? 's' : ''}</span>
        <span>&middot;</span>
        <span>{timeAgo(session.last_activity_at)}</span>
      </div>

      {hovered && (
        <div className="flex gap-2 mt-3">
          <button
            onClick={() => onResume(session)}
            className="flex-1 py-1.5 px-3 bg-emerald-600/20 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 hover:bg-emerald-600/30 transition-colors"
          >
            Resume Session
          </button>
          <button
            onClick={() => onEnd(session)}
            className="flex-1 py-1.5 px-3 bg-rose-600/20 border border-rose-500/30 rounded-lg text-xs text-rose-300 hover:bg-rose-600/30 transition-colors"
          >
            End Session
          </button>
        </div>
      )}
    </div>
  )
}
