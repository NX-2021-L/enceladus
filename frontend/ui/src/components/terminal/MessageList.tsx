import { useRef, useEffect } from 'react'
import type { TerminalTurn } from '../../types/terminal'
import { MessageBubble } from './MessageBubble'
import { CoordinationStateBadge } from '../shared/CoordinationStateBadge'

interface MessageListProps {
  turns: TerminalTurn[]
  pendingState?: string | null
  isPending?: boolean
}

export function MessageList({ turns, pendingState, isPending }: MessageListProps) {
  const bottomRef = useRef<HTMLDivElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [turns.length, pendingState])

  if (isPending) {
    return (
      <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">
        Loading conversation...
      </div>
    )
  }

  if (turns.length === 0 && !pendingState) {
    return (
      <div className="flex-1 flex items-center justify-center text-slate-500 text-sm px-4 text-center">
        No messages yet. Send a message to start the conversation.
      </div>
    )
  }

  return (
    <div ref={containerRef} className="flex-1 overflow-y-auto px-3 py-2 space-y-1">
      {turns.map((turn, i) => (
        <MessageBubble
          key={`${turn.turn_index}-${i}`}
          role={turn.role}
          content={turn.content}
          timestamp={turn.timestamp_utc || turn.timestamp}
        />
      ))}
      {pendingState && (
        <div className="flex justify-start mb-3">
          <div className="bg-slate-800 border border-slate-700/50 rounded-lg px-3 py-2 flex items-center gap-2">
            <div className="flex space-x-1">
              <span className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce [animation-delay:-0.3s]" />
              <span className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce [animation-delay:-0.15s]" />
              <span className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce" />
            </div>
            <CoordinationStateBadge state={pendingState} />
          </div>
        </div>
      )}
      <div ref={bottomRef} />
    </div>
  )
}
