/**
 * Coordination monitor page (ENC-TSK-L34 / B67 PWA2.0).
 *
 * Cards + PropertyFilter + Tabs (record-type split): sessions / agent types /
 * lessons / escalations / CRQ docs. Scoped to CRQ (coordination-request)
 * documents and session/agent/lesson/escalation records -- served by the
 * comp-coordination-api backend slice (src/api/coordination.ts), NOT the
 * tracker/documents corpus, the OpenSearch index, or /feed/corpus.
 *
 * The standalone Escalations menu item is deprecated by this page -- the
 * Escalations tab below is the one surface for that record type now.
 */
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearch } from '@tanstack/react-router'
import { Cards, PropertyFilter, Tabs } from '../design-system'
import { StatusChip } from '../components/StatusChip'
import { RecordCard } from '../components/RecordCard'
import { VirtualList } from '../components/VirtualList'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import {
  fetchAgentSessions,
  fetchAgentTypes,
  fetchCoordinationRequests,
  fetchEscalations,
  fetchLessons,
  type AgentSession,
  type AgentType,
  type CoordinationRequest,
  type EscalationRecord,
  type LessonRecord,
} from '../api/coordination'
import type { PropertyFilterQuery } from '../../../design-system-2/v2/components/PropertyFilter/PropertyFilter.jsx'
import { applyTokens } from './applyCoordinationFilter'
import './coordination.css'

const EMPTY_FILTER: PropertyFilterQuery = { tokens: [], operation: 'and' }

const coordinationRequestsQueryOptions = {
  queryKey: ['coordination', 'monitor'] as const,
  queryFn: ({ signal }: { signal: AbortSignal }) => fetchCoordinationRequests({ signal }),
}

const agentSessionsQueryOptions = {
  queryKey: ['coordination', 'agent-sessions'] as const,
  queryFn: ({ signal }: { signal: AbortSignal }) => fetchAgentSessions({}, { signal }),
}

const agentTypesQueryOptions = {
  queryKey: ['coordination', 'agent-types'] as const,
  queryFn: ({ signal }: { signal: AbortSignal }) => fetchAgentTypes(undefined, { signal }),
}

export function CoordinationRoute() {
  useDocumentTitle('Coordination')
  // ENC-TSK-M19: Home's "Requires io" queue deep-links here with
  // ?tab=escalations; any other/missing value falls back to the default.
  const { tab: initialTab } = useSearch({ from: '/coordination' })
  const [activeTabId, setActiveTabId] = useState(initialTab || 'sessions')
  const [filterQuery, setFilterQuery] = useState<PropertyFilterQuery>(EMPTY_FILTER)

  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)
  const projectId = projects[0]?.project_id ?? 'enceladus'

  const sessionsQuery = useQuery(agentSessionsQueryOptions)
  const agentTypesQuery = useQuery(agentTypesQueryOptions)
  const lessonsQuery = useQuery({
    queryKey: ['coordination', 'lessons', projectId] as const,
    queryFn: ({ signal }) => fetchLessons(projectId, { signal }),
  })
  const escalationsQuery = useQuery({
    queryKey: ['coordination', 'escalations', projectId] as const,
    queryFn: ({ signal }) => fetchEscalations(projectId, { signal }),
  })
  const crqQuery = useQuery(coordinationRequestsQueryOptions)

  // AC-16: React Compiler owns memoization -- no manual useMemo. These are
  // cheap array filters over small (<=200 row) datasets.
  const sessions = applyTokens(sessionsQuery.data ?? [], filterQuery)
  const agentTypes = applyTokens(agentTypesQuery.data ?? [], filterQuery)
  const lessons = applyTokens(lessonsQuery.data ?? [], filterQuery)
  const escalations = applyTokens(escalationsQuery.data ?? [], filterQuery)
  const crqDocs = applyTokens(crqQuery.data ?? [], filterQuery)

  const tabs = [
    {
      id: 'sessions',
      label: 'Sessions',
      count: sessions.length,
      content: (
        // ENC-TSK-M18 (AC-3): sessions is documented as a "<=200 row"
        // dataset (see AC-16 note below) rendered with a bare .map() before
        // this task -- VirtualList windows it past the 30-row threshold so
        // an active-multi-agent day doesn't mount 100+ RecordCard DOM nodes
        // at once.
        <div className="ev2-rc-grid ev2-rc-grid--2col">
          <VirtualList
            items={sessions}
            getKey={(row) => row.session_id}
            estimateSize={96}
            renderItem={(row) => (
              <RecordCard
                recordId={row.session_id}
                kindLabel={row.agent_type_id}
                description={row.runtime ? `Runtime: ${row.runtime}` : undefined}
                status={row.status}
                variant="standard"
              />
            )}
          />
        </div>
      ),
    },
    {
      id: 'agents',
      label: 'Agent types',
      count: agentTypes.length,
      content: (
        <Cards<AgentType>
          items={agentTypes}
          trackBy="agent_type_id"
          columns={2}
          cardDefinition={{
            header: (row) => row.agent_type_id,
            sections: [
              { id: 'surface', header: 'Surface', content: (row) => row.surface },
              { id: 'model', header: 'Model', content: (row) => row.model },
              { id: 'cost_tier', header: 'Cost tier', content: (row) => row.cost_tier },
              { id: 'status', header: 'Status', content: (row) => <StatusChip status={row.status} /> },
              { id: 'usage_count', header: 'Usage count', content: (row) => String(row.usage_count) },
            ],
          }}
        />
      ),
    },
    {
      id: 'lessons',
      label: 'Lessons',
      count: lessons.length,
      content: (
        <Cards<LessonRecord>
          items={lessons}
          trackBy="item_id"
          columns={2}
          cardDefinition={{
            header: (row) => row.title,
            sections: [
              { id: 'id', header: 'ID', content: (row) => row.item_id },
              { id: 'status', header: 'Status', content: (row) => <StatusChip status={row.status} /> },
              { id: 'provenance', header: 'Provenance', content: (row) => row.provenance },
            ],
          }}
        />
      ),
    },
    {
      id: 'escalations',
      label: 'Escalations',
      count: escalations.length,
      content: (
        <Cards<EscalationRecord>
          items={escalations}
          trackBy="item_id"
          columns={2}
          cardDefinition={{
            header: (row) => row.item_id ?? row.record_id ?? '(unknown)',
            sections: [
              { id: 'status', header: 'Status', content: (row) => <StatusChip status={row.status} /> },
              { id: 'target', header: 'Target record', content: (row) => row.target_record_id ?? '—' },
              { id: 'created_at', header: 'Created at', content: (row) => row.created_at },
            ],
          }}
        />
      ),
    },
    {
      id: 'crq',
      label: 'CRQ docs',
      count: crqDocs.length,
      content: (
        <Cards<CoordinationRequest>
          items={crqDocs}
          trackBy="request_id"
          columns={2}
          cardDefinition={{
            header: (row) => row.initiative_title || row.request_id,
            sections: [
              { id: 'id', header: 'Request ID', content: (row) => row.request_id },
              { id: 'state', header: 'State', content: (row) => <StatusChip status={row.state} /> },
              { id: 'project', header: 'Project', content: (row) => row.project_id },
              { id: 'updated_at', header: 'Updated at', content: (row) => row.updated_at },
            ],
          }}
        />
      ),
    },
  ]

  const anyLoading =
    sessionsQuery.isLoading ||
    agentTypesQuery.isLoading ||
    lessonsQuery.isLoading ||
    escalationsQuery.isLoading ||
    crqQuery.isLoading

  return (
    <div className="coordination-route">
      <header className="coordination-route__header">
        <p className="coordination-route__eyebrow">B67 PWA2.0 · Coordination</p>
        <h1 className="coordination-route__title">Coordination monitor</h1>
        <p className="coordination-route__subtitle">
          CRQ (coordination-request) documents and session / agent-type / lesson / escalation
          records, split by record type. Served by comp-coordination-api's dedicated list
          routes -- distinct from the tracker/documents/OpenSearch corpus.
        </p>
      </header>

      <PropertyFilter
        query={filterQuery}
        onChange={(event) => setFilterQuery(event.detail)}
        placeholder="Filter by field:value (e.g. status:claimed)"
      />

      {anyLoading && crqDocs.length === 0 && sessions.length === 0 && (
        <p className="coordination-route__empty">Loading coordination monitor data…</p>
      )}

      <Tabs tabs={tabs} activeTabId={activeTabId} onChange={(event) => setActiveTabId(event.detail.activeTabId)} />
    </div>
  )
}
