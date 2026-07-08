import { Suspense } from 'react'
import { useSuspenseQuery } from '@tanstack/react-query'
import { createRoute, type AnyRoute } from '@tanstack/react-router'
import { queryClient } from '../api/queryClient'
import {
  agentSessionsQueryOptions,
  agentTypesQueryOptions,
} from '../api/agentSessionsQueryOptions'
import type { AgentSession, AgentSessionStatus } from '../api/agentSessions'
import { KeyValuePairs, StatusIndicator, Table } from '../design-system'
import { SkeletonCard } from '../components/SkeletonCard'
import { useDocumentTitle } from '../hooks/useDocumentTitle'

/**
 * Agent detail page (ENC-TSK-L36). Lists the live, currently-claimed,
 * non-retired sessions of one agent type via the same coordination-api list
 * route L34 uses for its own listing page, filtered server-side with
 * `status=claimed` (retired sessions carry a distinct status value and are
 * excluded by that filter).
 *
 * Structured after routes/recordRoute.tsx's createRecordRoute factory: loader
 * primes the query cache via ensureQueryData, the component reads it back
 * with useSuspenseQuery (never `data?.`), and a route-level Suspense boundary
 * shows SkeletonCard for first paint.
 */

const SESSION_LIST_STATUS: AgentSessionStatus = 'claimed'

function statusIndicatorType(status: string): 'success' | 'stopped' | 'info' {
  if (status === 'claimed') return 'success'
  if (status === 'retired') return 'stopped'
  return 'info'
}

/**
 * Factory mirroring createRecordRoute's shape, minus project-scoping (agent
 * types are not project-scoped). Not registered here — router.tsx wiring is
 * owned centrally; see the coordinator report for the exact snippet.
 */
export function createAgentDetailRoute(config: {
  getParentRoute: () => AnyRoute
  path?: string
}): AnyRoute {
  const { getParentRoute, path = '/agent/$agentTypeId' } = config

  function AgentDetailComponent() {
    const { agentTypeId } = route.useParams() as { agentTypeId: string }
    const { data: sessions } = useSuspenseQuery(
      agentSessionsQueryOptions(agentTypeId, SESSION_LIST_STATUS),
    )
    const { data: agentTypes } = useSuspenseQuery(agentTypesQueryOptions('active'))
    const agentType = agentTypes.find((t) => t.agent_type_id === agentTypeId)
    // ENC-TSK-M25: agent types have no free-text "title" — surface is the
    // closest content descriptor after the id itself.
    useDocumentTitle(`${agentTypeId}: ${agentType?.surface ?? 'Agent'} sessions`)

    return (
      <div className="ev2-agent-detail">
        <h1>{agentTypeId}</h1>
        {agentType && (
          <KeyValuePairs
            columns={3}
            items={[
              { label: 'Surface', value: agentType.surface ?? '—' },
              { label: 'Model', value: agentType.model ?? '—', mono: true },
              { label: 'Cost tier', value: agentType.cost_tier ?? '—' },
            ]}
          />
        )}
        <Table<AgentSession>
          trackBy="session_id"
          header={`Claimed sessions (${sessions.length})`}
          empty="No claimed, non-retired sessions for this agent type"
          columnDefinitions={[
            {
              id: 'status',
              header: 'Status',
              cell: (row: AgentSession) => (
                <StatusIndicator type={statusIndicatorType(row.status)}>
                  {row.status}
                </StatusIndicator>
              ),
            },
            {
              id: 'session_id',
              header: 'Session ID',
              cell: (row: AgentSession) => row.session_id,
            },
            {
              id: 'runtime',
              header: 'Runtime',
              cell: (row: AgentSession) => row.runtime ?? '—',
            },
            {
              id: 'created_at',
              header: 'Created at',
              cell: (row: AgentSession) => row.created_at ?? '—',
            },
            {
              id: 'claimed_at',
              header: 'Claimed at',
              cell: (row: AgentSession) => row.claimed_at ?? '—',
            },
            {
              id: 'credential_id',
              header: 'Credential ID',
              cell: (row: AgentSession) => row.credential_id ?? '—',
            },
          ]}
          items={sessions}
        />
      </div>
    )
  }

  function RouteComponent() {
    return (
      <Suspense fallback={<SkeletonCard label="Loading agent sessions" />}>
        <AgentDetailComponent />
      </Suspense>
    )
  }

  const route: AnyRoute = createRoute({
    getParentRoute,
    path,
    loader: ({ params }) => {
      const { agentTypeId } = params as { agentTypeId: string }
      return Promise.all([
        queryClient.ensureQueryData(agentSessionsQueryOptions(agentTypeId, SESSION_LIST_STATUS)),
        queryClient.ensureQueryData(agentTypesQueryOptions('active')),
      ])
    },
    component: RouteComponent,
  })

  return route
}
