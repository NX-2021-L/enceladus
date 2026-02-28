import { useState, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import type { ActiveSessionState, TerminalTurn } from '../../types/terminal'
import { useSessionTurns, useActiveRequest, useSendMessage } from '../../hooks/useTerminal'
import { MessageList } from './MessageList'
import { ChatInputBar } from './ChatInputBar'
import { ManageConnectionButton } from './ManageConnectionButton'

const LS_KEY = 'enceladus:terminal_active_session'

function loadActiveSession(): ActiveSessionState | null {
  try {
    const raw = localStorage.getItem(LS_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw)
    if (parsed?.session_id) return parsed as ActiveSessionState
    return null
  } catch {
    return null
  }
}

export function TerminalChatWidget() {
  const navigate = useNavigate()
  const [activeSession, setActiveSession] = useState<ActiveSessionState | null>(loadActiveSession)
  const [activeRequestId, setActiveRequestId] = useState<string | null>(null)
  const [optimisticTurns, setOptimisticTurns] = useState<TerminalTurn[]>([])

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === LS_KEY) {
        setActiveSession(loadActiveSession())
        setOptimisticTurns([])
        setActiveRequestId(null)
      }
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const { turns: serverTurns, isPending: turnsPending, refetch: refetchTurns } = useSessionTurns(
    activeSession?.session_id,
  )
  const { state: requestState, isTerminal } = useActiveRequest(activeRequestId ?? undefined)
  const sendMutation = useSendMessage()

  useEffect(() => {
    if (isTerminal && activeRequestId) {
      refetchTurns()
      setActiveRequestId(null)
      setOptimisticTurns([])
    }
  }, [isTerminal, activeRequestId, refetchTurns])

  const allTurns = [...serverTurns, ...optimisticTurns]

  const handleSend = useCallback(
    (message: string) => {
      if (!activeSession) return

      const optimisticTurn: TerminalTurn = {
        turn_index: serverTurns.length + optimisticTurns.length,
        role: 'user',
        content: message,
        timestamp_utc: new Date().toISOString(),
      }
      setOptimisticTurns((prev) => [...prev, optimisticTurn])

      sendMutation.mutate(
        {
          sessionId: activeSession.session_id,
          message,
          projectId: activeSession.project_id,
          provider: activeSession.provider,
        },
        {
          onSuccess: (data) => {
            const requestId = data?.request?.request_id
            if (requestId) {
              setActiveRequestId(requestId)
            }
          },
          onError: () => {
            setOptimisticTurns((prev) => prev.filter((t) => t !== optimisticTurn))
          },
        },
      )
    },
    [activeSession, serverTurns.length, optimisticTurns.length, sendMutation],
  )

  if (!activeSession) {
    return (
      <div className="mx-4 mb-4">
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-slate-400">Terminal</h3>
            <ManageConnectionButton />
          </div>
          <p className="text-sm text-slate-500 mb-3">No active terminal session.</p>
          <button
            onClick={() => navigate('/terminal/manage')}
            className="w-full py-2 px-3 bg-purple-600/20 border border-purple-500/30 rounded-lg text-sm text-purple-300 hover:bg-purple-600/30 transition-colors"
          >
            Start a session
          </button>
        </div>
      </div>
    )
  }

  const pendingState = activeRequestId && requestState && !isTerminal ? requestState : null

  return (
    <div className="mx-4 mb-4">
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden flex flex-col" style={{ maxHeight: '400px' }}>
        <div className="flex items-center justify-between px-3 py-2 border-b border-slate-700/50">
          <div className="flex items-center gap-2 min-w-0">
            <span className={`w-2 h-2 rounded-full ${activeSession ? 'bg-emerald-400' : 'bg-slate-500'}`} />
            <span className="text-xs text-slate-400 truncate">
              {activeSession.provider} &middot; {activeSession.session_id.slice(0, 8)}
            </span>
          </div>
          <ManageConnectionButton />
        </div>

        <MessageList
          turns={allTurns}
          pendingState={pendingState}
          isPending={turnsPending}
        />

        <ChatInputBar
          onSend={handleSend}
          disabled={sendMutation.isPending || !!activeRequestId}
          placeholder={activeRequestId ? 'Waiting for response...' : 'Send a message...'}
        />
      </div>
    </div>
  )
}
