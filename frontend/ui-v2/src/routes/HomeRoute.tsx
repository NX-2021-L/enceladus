import { useQueries, useQuery, type UseQueryOptions } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { BarChart, Box, Cards, Grid, Header, KeyValuePairs, PieChart } from '../design-system'
import { feedCorpusByTypeQueryOptions, feedCorpusQueryOptions } from '../api/feedCorpusQueryOptions'
import { recordQueryOptions } from '../api/queryOptions'
import { documentHref, recordHrefForType } from './recordLink'
import { RecordId } from '../components/RecordId'
import { StatusChip } from '../components/StatusChip'
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

/**
 * B67 PWA 2.0 — Home dashboard (ENC-TSK-L30). Shared content model with the
 * desktop first-load home section per the AC: one entry Card per record/doc
 * type resolving to the most recent record of that type (ID + title +
 * truncated description), a recent-documents element, and dashboard-wide
 * charts. Sourced entirely from the already-live GET /api/v1/feed/corpus
 * endpoint (ENC-TSK-L23) — no new backend surface.
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

export function HomeRoute() {
  // Dashboard-wide facets (record_type / status counts) — a limit:1 request
  // is enough since the backend computes facets over the whole filtered set
  // before slicing to `limit` (backend/lambda/feed_query/corpus.py).
  const facetsQuery = useQuery(feedCorpusQueryOptions({ limit: 1 }))

  // Recent documents element — top N documents by updated_at.
  const recentDocsQuery = useQuery(feedCorpusByTypeQueryOptions('document', { limit: 8 }))

  // Most-recent-of-each-type identity rows (id/title/updated_at), one
  // targeted query per type so correctness doesn't depend on all six types
  // appearing within a single global recency window.
  const perTypeResults = useQueries({
    queries: DASHBOARD_RECORD_TYPES.map((type) => feedCorpusByTypeQueryOptions(type, { limit: 1 })),
  })

  // AC-16 — React Compiler owns memoization; this is a plain derived value,
  // not a hand-written useMemo.
  const mostRecentByType: Partial<Record<RecordType, FeedCorpusItem>> = {}
  DASHBOARD_RECORD_TYPES.forEach((type, i) => {
    const item = perTypeResults[i]?.data?.items?.[0]
    if (item) mostRecentByType[type] = item
  })

  // Full-body detail fetch for each most-recent identity row, so the card can
  // show a truncated *description* — the feed corpus deliberately omits
  // description text (see corpus.py _handle_snapshot docstring: "stops
  // leaking descriptions") to keep the sync payload small.
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
  const totalRecords = facetsQuery.data?.total_matches ?? 0

  const entryCardDefinition = {
    header: (row: EntryCardRow) =>
      row.recordId ? (
        <Link to={row.href} style={{ textDecoration: 'none', color: 'var(--fg-display)' }}>
          {row.label}
        </Link>
      ) : (
        <span style={{ color: 'var(--fg-muted)' }}>{row.label}</span>
      ),
    sections: [
      {
        id: 'id',
        header: 'Most recent',
        content: (row: EntryCardRow) =>
          row.recordId ? (
            <span
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-2)',
                flexWrap: 'wrap',
              }}
            >
              <RecordId id={row.recordId} />
              {row.status ? <StatusChip status={row.status} /> : null}
            </span>
          ) : (
            '—'
          ),
      },
      {
        id: 'title',
        header: 'Title',
        content: (row: EntryCardRow) => row.title || '—',
      },
      {
        id: 'description',
        header: 'Description',
        content: (row: EntryCardRow) => row.description || '—',
      },
    ],
  }

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

  return (
    <div>
      <Header
        variant="h1"
        description="One card per record/document type -> the most recent of each, a recent-documents feed, and dashboard-wide counts across every governed primitive."
      >
        Home
      </Header>

      <div style={{ margin: 'var(--space-6) 0' }}>
        <KeyValuePairs
          columns={3}
          items={[
            { label: 'Tracked records + documents', value: totalRecords, mono: true },
            { label: 'Record types', value: DASHBOARD_RECORD_TYPES.length, mono: true },
            { label: 'Recent documents shown', value: recentDocuments.length, mono: true },
          ]}
        />
      </div>

      <Grid gridDefinition={[{ colspan: 8 }, { colspan: 4 }]}>
        <div>
          <Box variant="strong" margin="0 0 var(--space-2)">
            Entry cards — most recent per type
          </Box>
          <Cards items={entryCards} trackBy="type" columns={2} cardDefinition={entryCardDefinition} />
        </div>

        <div>
          <Box variant="strong" margin="0 0 var(--space-2)">
            Recent documents
          </Box>
          <Cards
            items={recentDocuments}
            trackBy="record_id"
            columns={1}
            cardDefinition={recentDocDefinition}
          />
        </div>
      </Grid>

      <Grid gridDefinition={[{ colspan: 6 }, { colspan: 6 }]}>
        <div style={{ marginTop: 'var(--space-8)' }}>
          <BarChart
            title="Records by type"
            subtitle="Dashboard-wide counts across every governed primitive"
            xDomain={typeSeries.labels.map((label) => DASHBOARD_TYPE_LABEL[label as RecordType] ?? label)}
            series={[{ title: 'Count', data: typeSeries.values }]}
            height={220}
          />
        </div>
        <div style={{ marginTop: 'var(--space-8)' }}>
          <PieChart
            title="Records by status"
            subtitle="Across all tracker + document records"
            data={statusPie}
          />
        </div>
      </Grid>
    </div>
  )
}
