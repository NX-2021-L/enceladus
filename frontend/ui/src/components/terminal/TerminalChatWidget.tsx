import { useState, useCallback, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import type { ActiveSessionState, TerminalTurn } from '../../types/terminal'
import { useSessionTurns, useActiveRequest, useSendMessage } from '../../hooks/useTerminal'
import { MessageList } from './MessageList'
import { ChatInputBar } from './ChatInputBar'
import { ManageConnectionButton } from './ManageConnectionButton'

const LS_KEY = 'enceladus:terminal_active_session'
const TURNS_LS_PREFIX = 'enceladus:terminal_turns:'

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

function loadLocalTurns(sessionId: string): TerminalTurn[] {
  try {
    const raw = localStorage.getItem(TURNS_LS_PREFIX + sessionId)
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

function saveLocalTurns(sessionId: string, turns: TerminalTurn[]) {
  try {
    localStorage.setItem(TURNS_LS_PREFIX + sessionId, JSON.stringify(turns))
  } catch {
    /* localStorage quota exceeded — silent fail */
  }
}

export function TerminalChatWidget() {
  const navigate = useNavigate()
  const [activeSession, setActiveSession] = useState<ActiveSessionState | null>(loadActiveSession)
  const [activeRequestId, setActiveRequestId] = useState<string | null>(null)
  const [localTurns, setLocalTurns] = useState<TerminalTurn[]>(() =>
    activeSession ? loadLocalTurns(activeSession.session_id) : [],
  )

  // Whether the session needs MCP initialization (empty project_id)
  const needsInit = activeSession ? activeSession.project_id === '' : false

  // Listen for active session changes from other tabs/components
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === LS_KEY) {
        const session = loadActiveSession()
        setActiveSession(session)
        setLocalTurns(session ? loadLocalTurns(session.session_id) : [])
        setActiveRequestId(null)
      }
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const { turns: serverTurns, isPending: turnsPending } = useSessionTurns(
    activeSession?.session_id,
  )
  const { state: requestState, isTerminal, result: requestResult } = useActiveRequest(
    activeRequestId ?? undefined,
  )
  const sendMutation = useSendMessage()

  // When request reaches terminal state, handle response and clear request tracking
  useEffect(() => {
    if (!isTerminal || !activeRequestId || !activeSession) return

    // Extract assistant response from the coordination result
    const summary = requestResult?.summary
    if (summary) {
      setLocalTurns((prev) => {
        const assistantTurn: TerminalTurn = {
          turn_index: prev.length,
          role: 'assistant',
          content: summary,
          timestamp_utc: new Date().toISOString(),
        }
        const updated = [...prev, assistantTurn]
        saveLocalTurns(activeSession.session_id, updated)
        return updated
      })
    }

    setActiveRequestId(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isTerminal, activeRequestId])

  // Merge server turns (S3 archive) with local turns, deduplicated
  const allTurns = useMemo(() => {
    const merged = [...serverTurns]
    for (const lt of localTurns) {
      const exists = merged.some(
        (st) => st.role === lt.role && st.content === lt.content,
      )
      if (!exists) merged.push(lt)
    }
    return merged.sort((a, b) => a.turn_index - b.turn_index)
  }, [serverTurns, localTurns])

  // Send a raw message to the active session
  const sendRawMessage = useCallback(
    (message: string, session: ActiveSessionState) => {
      const userTurn: TerminalTurn = {
        turn_index: localTurns.length,
        role: 'user',
        content: message,
        timestamp_utc: new Date().toISOString(),
      }
      setLocalTurns((prev) => {
        const updated = [...prev, userTurn]
        saveLocalTurns(session.session_id, updated)
        return updated
      })

      sendMutation.mutate(
        {
          sessionId: session.session_id,
          message,
          projectId: session.project_id,
          provider: session.provider,
        },
        {
          onSuccess: (data) => {
            const requestId = data?.request?.request_id
            if (requestId) {
              setActiveRequestId(requestId)
            }
          },
          onError: () => {
            // Remove the failed user turn
            setLocalTurns((prev) => {
              const updated = prev.filter((t) => t !== userTurn)
              if (activeSession) saveLocalTurns(activeSession.session_id, updated)
              return updated
            })
          },
        },
      )
    },
    [activeSession, localTurns.length, sendMutation],
  )

  const handleSend = useCallback(
    (message: string) => {
      if (!activeSession) return

      if (needsInit) {
        // User typed the project name — update session and auto-send init prompt
        const projectId = message.trim().toLowerCase()
        const updatedSession: ActiveSessionState = {
          ...activeSession,
          project_id: projectId,
        }
        localStorage.setItem(LS_KEY, JSON.stringify(updatedSession))
        setActiveSession(updatedSession)

        const initPrompt = `set env variable $PROJECT=${projectId}`
        sendRawMessage(initPrompt, updatedSession)
        return
      }

      sendRawMessage(message, activeSession)
    },
    [activeSession, needsInit, sendRawMessage],
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

  // Compute pending indicator covering all async phases
  let pendingIndicator: string | null = null
  if (sendMutation.isPending) {
    pendingIndicator = 'sending'
  } else if (activeRequestId && !requestState) {
    pendingIndicator = 'dispatching'
  } else if (activeRequestId && requestState && !isTerminal) {
    pendingIndicator = requestState
  }

  // Compute placeholder text based on session state
  let placeholder: string
  if (needsInit) {
    placeholder = 'What is the current project?'
  } else if (activeRequestId) {
    placeholder = 'Waiting for response...'
  } else {
    placeholder = 'Send a message...'
  }

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
          pendingState={pendingIndicator}
          isPending={turnsPending}
        />

        <ChatInputBar
          onSend={handleSend}
          disabled={sendMutation.isPending || !!activeRequestId}
          placeholder={placeholder}
        />
      </div>
    </div>
  )
}
