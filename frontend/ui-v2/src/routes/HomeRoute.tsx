import { useState } from 'react'
import { useQueries, useQuery, type UseQueryOptions } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { BarChart, Box, Cards, Header, PieChart, Tabs } from '../design-system'
import { feedCorpusByTypeQueryOptions, feedCorpusQueryOptions } from '../api/feedCorpusQueryOptions'
import { recordQueryOptions } from '../api/queryOptions'
import { fetchEscalations } from '../api/coordination'
import {
  fetchAwaitingCheckoutCount,
  fetchOpenP0P1Count,
  fetchPausedApprovals,
  fetchStaleLocks,
} from '../api/homeQueue'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { documentHref, recordHrefForType } from './recordLink'
import { RecordId } from '../components/RecordId'
import { RecordCard } from '../components/RecordCard'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { pausedApprovalRows, pendingEscalationRows, staleLockRows, type QueueRow } from './homeQueue'
import { FEED_SEARCH_DEFAULTS, serializeFilterQuery, type FeedRouteSearch } from '../search/feedSearchParams'
import {
  DASHBOARD_RECORD_TYPES,
  DASHBOARD_TYPE_LABEL,
  facetToChartSeries,
  facetToPieData,
  sortRecentDocuments,
  truncateDescription,
} from './homeDashboard'
import type {
  Document,
  Feature,
  Issue,
  Lesson,
  Plan,
  RecordType,
  Task,
} from '../types/records'
import type { FeedCorpusItem } from '../sync/types'
import './home.css'

/**
 * Home dashboard (ENC-TSK-M19 / UX-B1, superseding the desktop-first
 * ENC-TSK-L30 build). Mobile-first: 360px is the base viewport. Leads with
 * the "Requires io" action queue (escalations + two documented data-gap
 * rows) and a compact counts strip above the fold; most-recent-per-type +
 * dashboard charts recede into a below-fold Tabs section. Desktop
 * projection reference: Home-Redesign.dc.html (layout intent only).
 */

type DetailRecord = Task | Issue | Feature | Plan | Lesson | Document

const NOOP_QUERY = {
  queryFn: async () => null,
  enabled: false,
} as const

function detailQueryFor(
  type: RecordType,
  summary: FeedCorpusItem | undefined,
): UseQueryOptions<DetailRecord | null, Error, DetailRecord | null, readonly unknown[]> {
  if (!summary) {
    return { queryKey: ['home', 'detail', 'pending', type], ...NOOP_QUERY }
  }
  const options = (() => {
    switch (type) {
      case 'task':
        return recordQueryOptions.task(summary.project_id, summary.record_id)
      case 'issue':
        return recordQueryOptions.issue(summary.project_id, summary.record_id)
      case 'feature':
        return recordQueryOptions.feature(summary.project_id, summary.record_id)
      case 'plan':
        return recordQueryOptions.plan(summary.project_id, summary.record_id)
      case 'lesson':
        return recordQueryOptions.lesson(summary.project_id, summary.record_id)
      case 'document':
        return recordQueryOptions.document(summary.record_id)
      default:
        return { queryKey: ['home', 'detail', 'pending', type], ...NOOP_QUERY }
    }
  })()
  return options as UseQueryOptions<DetailRecord | null, Error, DetailRecord | null, readonly unknown[]>
}

/** Lesson has no `description` field (it has `observation`/`insight`) —
 * normalize every detail shape to a single description string for the card. */
function descriptionOf(type: RecordType, record: DetailRecord | null | undefined): string {
  if (!record) return ''
  if (type === 'lesson') return (record as Lesson).observation ?? ''
  return (record as Task | Issue | Feature | Plan | Document).description ?? ''
}

function statusOf(record: DetailRecord | null | undefined): string | undefined {
  if (!record) return undefined
  return (record as { status?: string }).status
}

interface EntryCardRow {
  type: RecordType
  label: string
  recordId: string
  title: string
  description: string
  status?: string
  href: string
}

/** Filtered-view /feed searches for the counts strip (ENC-FTR-130 Band-B).
 * Tokens mirror the exact server-side semantics each count tile's own fetch
 * uses (api/homeQueue.ts), so the destination list matches the number above
 * it: "Open P0/P1" = status=open AND priority in (P0,P1); "Awaiting
 * checkout" = status=open AND record_type=task AND checkout_state !=
 * checked_out. */
const OPEN_SEARCH: FeedRouteSearch = {
  ...FEED_SEARCH_DEFAULTS,
  f: serializeFilterQuery({
    tokens: [
      { propertyKey: 'status', operator: '=', value: 'open' },
      { propertyKey: 'priority', operator: 'in', value: 'p0,p1' },
    ],
    operation: 'and',
  }),
}
// ENC-TSK-M36 (feed data-truth, AC-3): `fetchAwaitingCheckoutCount` measures
// a SINGLE project (api/homeQueue.ts — GET /api/v1/tracker/{projectId}...),
// but this token set used to omit project_id entirely, so the tile's link
// opened an UNSCOPED, cross-project Feed view — any other project's
// awaiting-checkout tasks counted toward the number shown there even though
// the tile itself never counted them. Scoping the destination filter to the
// same project the count came from is what makes the two numbers agree.
export function openTasksSearchFor(projectId: string): FeedRouteSearch {
  return {
    ...FEED_SEARCH_DEFAULTS,
    f: serializeFilterQuery({
      tokens: [
        { propertyKey: 'status', operator: '=', value: 'open' },
        { propertyKey: 'record_type', operator: '=', value: 'task' },
        { propertyKey: 'checkout_state', operator: '!=', value: 'checked_out' },
        { propertyKey: 'project_id', operator: '=', value: projectId },
      ],
      operation: 'and',
    }),
  }
}

function QueueCard({ row }: { row: QueueRow }) {
  if (row.gap) {
    return (
      <div className="home-route__gap-card">
        <span className="home-route__gap-badge">Data gap</span>
        <p className="home-route__gap-title">{row.title}</p>
        <p className="home-route__gap-desc">{row.description}</p>
      </div>
    )
  }
  return (
    <RecordCard
      recordId={row.id}
      kindLabel={row.kindLabel}
      title={row.title}
      description={row.description}
      status={row.status}
      href={row.href}
      variant="standard"
    />
  )
}

export function HomeRoute() {
  useDocumentTitle('Home')
  const [recentTabId, setRecentTabId] = useState('entry-cards')

  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)
  const projectId = projects[0]?.project_id ?? 'enceladus'

  // "Requires io" queue — escalations share the exact queryKey CoordinationRoute
  // uses for its Escalations tab, so the two pages share one cache entry.
  const escalationsQuery = useQuery({
    queryKey: ['coordination', 'escalations', projectId] as const,
    queryFn: ({ signal }) => fetchEscalations(projectId, { signal }),
  })
  // ENC-TSK-M27: paused v3-prod Environment approvals + stale-checkout locks,
  // replacing the M19 "Data gap" placeholder rows with live fetches.
  const pausedApprovalsQuery = useQuery({
    queryKey: ['home', 'queue', 'paused-approvals'] as const,
    queryFn: ({ signal }) => fetchPausedApprovals({ signal }),
  })
  const staleLocksQuery = useQuery({
    queryKey: ['home', 'queue', 'stale-locks'] as const,
    queryFn: ({ signal }) => fetchStaleLocks({ signal }),
  })
  const queueRows: QueueRow[] = [
    ...pendingEscalationRows(escalationsQuery.data ?? []),
    ...pausedApprovalRows(pausedApprovalsQuery.data ?? []),
    ...staleLockRows(staleLocksQuery.data ?? []),
  ]

  // Actionable counts strip.
  const openP0P1Query = useQuery({
    queryKey: ['home', 'open-p0-p1'] as const,
    queryFn: ({ signal }) => fetchOpenP0P1Count({ signal }),
  })
  const awaitingCheckoutQuery = useQuery({
    queryKey: ['home', 'awaiting-checkout', projectId] as const,
    queryFn: ({ signal }) => fetchAwaitingCheckoutCount(projectId, { signal }),
  })

  // Below-fold "recent activity" — dashboard-wide facets, most-recent-per-type
  // entry cards, and recent documents. Unchanged data model from the prior
  // ENC-TSK-L30 build (routes/homeDashboard.ts); only the placement moved.
  // Dashboard-wide facets (record_type / status counts) — a limit:1 request
  // is enough since the backend computes facets over the whole filtered set
  // before slicing to `limit` (backend/lambda/feed_query/corpus.py).
  const facetsQuery = useQuery(feedCorpusQueryOptions({ limit: 1 }))
  const recentDocsQuery = useQuery(feedCorpusByTypeQueryOptions('document', { limit: 8 }))
  const perTypeResults = useQueries({
    queries: DASHBOARD_RECORD_TYPES.map((type) => feedCorpusByTypeQueryOptions(type, { limit: 1 })),
  })

  const mostRecentByType: Partial<Record<RecordType, FeedCorpusItem>> = {}
  DASHBOARD_RECORD_TYPES.forEach((type, i) => {
    const item = perTypeResults[i]?.data?.items?.[0]
    if (item) mostRecentByType[type] = item
  })

  const detailResults = useQueries({
    queries: DASHBOARD_RECORD_TYPES.map((type) => detailQueryFor(type, mostRecentByType[type])),
  })

  const entryCards: EntryCardRow[] = DASHBOARD_RECORD_TYPES.map((type, i) => {
    const summary = mostRecentByType[type]
    const detail = detailResults[i]?.data as DetailRecord | null | undefined
    const recordId = summary?.record_id ?? ''
    const title = detail?.title ?? summary?.title ?? ''
    return {
      type,
      label: DASHBOARD_TYPE_LABEL[type],
      recordId,
      title,
      description: truncateDescription(descriptionOf(type, detail)),
      status: statusOf(detail),
      href: recordId
        ? type === 'document'
          ? documentHref(recordId)
          : recordHrefForType(summary?.project_id ?? null, type, recordId)
        : '',
    }
  })

  const recentDocuments = sortRecentDocuments(recentDocsQuery.data?.items ?? [], 8)

  const typeSeries = facetToChartSeries(
    facetsQuery.data?.facets?.record_type,
    DASHBOARD_RECORD_TYPES,
  )
  const statusPie = facetToPieData(facetsQuery.data?.facets?.status)

  const recentDocDefinition = {
    header: (doc: FeedCorpusItem) => (
      <Link to={documentHref(doc.record_id)} style={{ textDecoration: 'none', color: 'var(--fg-display)' }}>
        {doc.title}
      </Link>
    ),
    sections: [
      {
        id: 'id',
        header: 'Document',
        content: (doc: FeedCorpusItem) => <RecordId id={doc.record_id} />,
      },
      {
        id: 'updated',
        header: 'Updated',
        content: (doc: FeedCorpusItem) => doc.updated_at ?? '—',
      },
    ],
  }

  const recentTabs = [
    {
      id: 'entry-cards',
      label: 'Most recent per type',
      count: entryCards.length,
      content: (
        <div className="ev2-rc-grid ev2-rc-grid--2col">
          {entryCards.map((row) => (
            <RecordCard
              key={row.type}
              recordId={row.recordId || row.label}
              recordType={row.type}
              kindLabel={row.label}
              title={row.title}
              description={row.description}
              status={row.status}
              href={row.href || undefined}
              variant="standard"
            />
          ))}
        </div>
      ),
    },
    {
      id: 'recent-docs',
      label: 'Recent documents',
      count: recentDocuments.length,
      content: (
        <Cards
          items={recentDocuments}
          trackBy="record_id"
          columns={1}
          cardDefinition={recentDocDefinition}
        />
      ),
    },
    {
      id: 'charts',
      label: 'Dashboard charts',
      content: (
        <>
          <div style={{ marginTop: 'var(--space-4)' }}>
            <BarChart
              title="Records by type"
              subtitle="Dashboard-wide counts across every governed primitive"
              xDomain={typeSeries.labels.map((label) => DASHBOARD_TYPE_LABEL[label as RecordType] ?? label)}
              series={[{ title: 'Count', data: typeSeries.values }]}
              height={220}
            />
          </div>
          <div style={{ marginTop: 'var(--space-6)' }}>
            <PieChart
              title="Records by status"
              subtitle="Across all tracker + document records"
              data={statusPie}
            />
          </div>
        </>
      ),
    },
  ]

  return (
    <div className="home-route">
      <Header
        variant="h1"
        description="Requires io leads — escalations and other human-only unblocks come first; most-recent activity recedes below."
      >
        Home
      </Header>

      <section className="home-route__queue" aria-label="Requires io">
        <div className="home-route__section-label home-route__section-label--alert">
          Requires io
          <span className="home-route__section-hint">
            {queueRows.length} item{queueRows.length === 1 ? '' : 's'} only the principal can unblock
          </span>
        </div>
        {escalationsQuery.isLoading ? (
          <p className="home-route__empty">Loading escalations…</p>
        ) : (
          <div className="home-route__queue-list">
            {queueRows.map((row) => (
              <QueueCard key={row.id} row={row} />
            ))}
          </div>
        )}
      </section>

      <section className="home-route__counts" aria-label="Actionable counts">
        <Link to="/feed" search={OPEN_SEARCH} className="home-route__count-tile">
          <span className="home-route__count-value">
            {openP0P1Query.isLoading ? '…' : (openP0P1Query.data ?? 0)}
          </span>
          <span className="home-route__count-label">Open P0/P1</span>
        </Link>
        <Link to="/feed" search={openTasksSearchFor(projectId)} className="home-route__count-tile">
          <span className="home-route__count-value">
            {awaitingCheckoutQuery.isLoading ? '…' : (awaitingCheckoutQuery.data ?? 0)}
          </span>
          <span className="home-route__count-label">Awaiting checkout</span>
        </Link>
      </section>
      <p className="home-route__counts-note">
        Counts are exact (server-computed). Their links open Feed pre-filtered to match — results
        may lag briefly behind the count while the local feed snapshot finishes syncing.
      </p>

      <section className="home-route__recent" aria-label="Recent activity">
        <Box variant="strong" margin="0 0 var(--space-2)">
          Recent activity
        </Box>
        <Tabs
          tabs={recentTabs}
          activeTabId={recentTabId}
          onChange={(event) => setRecentTabId(event.detail.activeTabId)}
        />
      </section>
    </div>
  )
}
