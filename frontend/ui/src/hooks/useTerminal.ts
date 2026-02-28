import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  terminalKeys,
  fetchTerminalSessions,
  fetchSessionTurns,
  sendChatMessage,
  fetchCoordinationRequestState,
} from '../api/terminal'
import { isSessionExpiredError } from '../lib/authSession'

const TERMINAL_STATES = new Set(['succeeded', 'failed', 'cancelled', 'dead_letter'])

export function useTerminalSessions() {
  const query = useQuery({
    queryKey: terminalKeys.sessions,
    queryFn: fetchTerminalSessions,
    refetchInterval: 5000,
    retry: (count, error) => {
      if (isSessionExpiredError(error)) return false
      return count < 2
    },
    throwOnError: false,
    meta: { suppressSessionExpired: true },
  })

  return {
    sessions: query.data?.sessions ?? [],
    generatedAt: query.data?.generated_at ?? null,
    isPending: query.isPending,
    isError: query.isError,
  }
}

export function useSessionTurns(sessionId: string | undefined) {
  const query = useQuery({
    queryKey: terminalKeys.turns(sessionId ?? ''),
    queryFn: () => fetchSessionTurns(sessionId!),
    enabled: !!sessionId,
    staleTime: 30_000,
    retry: (count, error) => {
      if (isSessionExpiredError(error)) return false
      return count < 2
    },
    throwOnError: false,
    meta: { suppressSessionExpired: true },
  })

  return {
    turns: query.data?.turns ?? [],
    isPending: query.isPending,
    isError: query.isError,
    refetch: query.refetch,
  }
}

export function useActiveRequest(requestId: string | undefined) {
  const query = useQuery({
    queryKey: terminalKeys.activeRequest(requestId ?? ''),
    queryFn: () => fetchCoordinationRequestState(requestId!),
    enabled: !!requestId,
    refetchInterval: (query) => {
      const state = query.state.data?.request?.state
      if (state && TERMINAL_STATES.has(state)) return false
      return 3000
    },
    retry: (count, error) => {
      if (isSessionExpiredError(error)) return false
      return count < 2
    },
    throwOnError: false,
    meta: { suppressSessionExpired: true },
  })

  const state = query.data?.request?.state ?? null
  const isTerminal = state !== null && TERMINAL_STATES.has(state)

  return {
    state,
    result: query.data?.request?.result ?? null,
    isTerminal,
    isPending: query.isPending,
    isError: query.isError,
  }
}

export function useSendMessage() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      sessionId,
      message,
      projectId,
      provider,
    }: {
      sessionId: string
      message: string
      projectId: string
      provider: string
    }) => sendChatMessage(sessionId, message, projectId, provider),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: terminalKeys.turns(variables.sessionId) })
    },
  })
}
