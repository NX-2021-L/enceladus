import { useState, useCallback, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import type { TerminalProvider, TerminalSession, ActiveSessionState } from '../types/terminal'
import { useTerminalSessions } from '../hooks/useTerminal'
import { ProviderCard } from '../components/terminal/ProviderCard'
import { SessionCard } from '../components/terminal/SessionCard'
import { FreshnessBadge } from '../components/shared/FreshnessBadge'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'

const LS_KEY = 'enceladus:terminal_active_session'
const TURNS_LS_PREFIX = 'enceladus:terminal_turns:'

const PROVIDERS: TerminalProvider[] = [
  {
    id: 'openai_codex',
    name: 'OpenAI Codex',
    execution_mode: 'codex_full_auto',
    description: 'Full automation via Codex on EC2',
  },
  {
    id: 'claude_agent_sdk',
    name: 'Claude Agent SDK',
    execution_mode: 'claude_agent_sdk',
    description: 'Anthropic Claude headless agent',
  },
]

export function TerminalManagePage() {
  const navigate = useNavigate()
  const { sessions, generatedAt, isPending, isError } = useTerminalSessions()
  const [endedSessionIds, setEndedSessionIds] = useState<Set<string>>(new Set())

  const setActiveSession = useCallback(
    (state: ActiveSessionState) => {
      localStorage.setItem(LS_KEY, JSON.stringify(state))
      window.dispatchEvent(new StorageEvent('storage', { key: LS_KEY }))
      navigate('/')
    },
    [navigate],
  )

  const handleStartSession = useCallback(
    (provider: TerminalProvider) => {
      const sessionId = crypto.randomUUID()
      setActiveSession({
        session_id: sessionId,
        provider: provider.id,
        project_id: '', // empty signals needs initialization (ISS-067)
      })
    },
    [setActiveSession],
  )

  const handleResumeSession = useCallback(
    (session: TerminalSession) => {
      setActiveSession({
        session_id: session.session_id,
        provider: session.provider,
        project_id: session.project_id,
      })
    },
    [setActiveSession],
  )

  const handleEndSession = useCallback(
    (session: TerminalSession) => {
      // Clear from active session if it's the current one
      try {
        const raw = localStorage.getItem(LS_KEY)
        if (raw) {
          const active = JSON.parse(raw) as ActiveSessionState
          if (active.session_id === session.session_id) {
            localStorage.removeItem(LS_KEY)
            window.dispatchEvent(new StorageEvent('storage', { key: LS_KEY }))
          }
        }
      } catch {
        // ignore
      }

      // Clear local chat history for this session
      localStorage.removeItem(TURNS_LS_PREFIX + session.session_id)

      // Hide the session card from the list
      setEndedSessionIds((prev) => new Set([...prev, session.session_id]))
    },
    [],
  )

  // Filter out ended sessions from the visible list
  const visibleSessions = useMemo(
    () => sessions.filter((s) => !endedSessionIds.has(s.session_id)),
    [sessions, endedSessionIds],
  )

  if (isPending) return <LoadingState />
  if (isError) return <ErrorState />

  return (
    <div className="p-4 space-y-6">
      <div>
        <h2 className="text-sm font-medium text-slate-400 mb-3">Providers</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {PROVIDERS.map((p) => (
            <ProviderCard key={p.id} provider={p} onStartSession={handleStartSession} />
          ))}
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-medium text-slate-400">
            Sessions ({visibleSessions.length})
          </h2>
          {generatedAt && <FreshnessBadge generatedAt={generatedAt} />}
        </div>

        {visibleSessions.length === 0 ? (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-6 text-center">
            <p className="text-sm text-slate-500">No terminal sessions found.</p>
            <p className="text-xs text-slate-600 mt-1">Start a new session from a provider above.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {visibleSessions.map((s) => (
              <SessionCard
                key={s.session_id}
                session={s}
                onResume={handleResumeSession}
                onEnd={handleEndSession}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
