/**
 * TanStack Query factories for the agent detail page (ENC-TSK-L36). Mirrors
 * the queryOptions.ts convention: route loader calls
 * `queryClient.ensureQueryData(...)` and the route component calls
 * `useSuspenseQuery(...)` against the same query key, so there is no
 * loader/component double-fetch and no `data?.` optional chaining.
 */

import { queryOptions } from '@tanstack/react-query'
import {
  fetchAgentSessions,
  fetchAgentTypes,
  type AgentSession,
  type AgentSessionStatus,
  type AgentType,
} from './agentSessions'

export const agentSessionsKeys = {
  all: ['agent-sessions'] as const,
  list: (agentTypeId: string, status: AgentSessionStatus) =>
    ['agent-sessions', agentTypeId, status] as const,
}

export const agentTypesKeys = {
  all: ['agent-types'] as const,
  list: (status: string) => ['agent-types', status] as const,
}

/** Sessions of one agent type, filtered to a status (default 'claimed' = live, non-retired). */
export const agentSessionsQueryOptions = (
  agentTypeId: string,
  status: AgentSessionStatus = 'claimed',
) =>
  queryOptions<AgentSession[]>({
    queryKey: agentSessionsKeys.list(agentTypeId, status),
    queryFn: ({ signal }) => fetchAgentSessions(agentTypeId, status, { signal }),
    // Live view — keep this fresh rather than relying on the global 2min staleTime.
    staleTime: 15 * 1000,
    refetchInterval: 15 * 1000,
  })

/** Agent types roster, used to resolve the current type's surface/model/cost_tier. */
export const agentTypesQueryOptions = (status = 'active') =>
  queryOptions<AgentType[]>({
    queryKey: agentTypesKeys.list(status),
    queryFn: ({ signal }) => fetchAgentTypes(status, { signal }),
  })
