import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { changelogHistoryQueryOptions, type ChangelogEntry } from '../api/changelog'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { Container, Header, Table } from '../design-system'
import type { TableColumnDefinition } from '../../../design-system-2/v2/components/Table/Table'

/**
 * Project page route target. There is no per-project detail route in ui-v2
 * yet (`/projects` is still the shell's placeholder list, ENC-TSK-K21
 * scaffold), so this mirrors the legacy app's convention
 * (`frontend/ui/src/lib/routes.tsx` -> `/projects/:projectId`,
 * `ProjectDetailPage.tsx`). Once ui-v2 grows a real per-project detail route
 * this should be swapped for the shared route-link helper in `recordLink.ts`.
 */
function projectHref(projectId: string): string {
  return `/projects/${encodeURIComponent(projectId)}`
}

function formatDeployedAt(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

const CHANGE_TYPE_LABEL: Record<ChangelogEntry['change_type'], string> = {
  major: 'Major',
  minor: 'Minor',
  patch: 'Patch',
}

/** `spec_id` is only unique within a project — compose a table-row-unique id. */
export type ChangelogRow = ChangelogEntry & { id: string }

export function toChangelogRows(entries: ChangelogEntry[]): ChangelogRow[] {
  return entries.map((entry) => ({ ...entry, id: `${entry.project_id}-${entry.spec_id}` }))
}

export function buildChangelogColumns(
  projectNameById: Map<string, string>,
): TableColumnDefinition<ChangelogRow>[] {
  return [
    {
      id: 'project',
      header: 'Project',
      sortingField: 'project_id',
      cell: (entry) => (
        <Link to={projectHref(entry.project_id)} className="ev2-changelog__project-link">
          {projectNameById.get(entry.project_id) ?? entry.project_id}
        </Link>
      ),
    },
    {
      id: 'version',
      header: 'Version',
      sortingField: 'version',
      cell: (entry) => <span className="ev2-table__mono">{entry.version}</span>,
    },
    {
      id: 'change_type',
      header: 'Type',
      sortingField: 'change_type',
      cell: (entry) => CHANGE_TYPE_LABEL[entry.change_type] ?? entry.change_type,
    },
    {
      id: 'release_summary',
      header: 'Summary',
      cell: (entry) => entry.release_summary,
    },
    {
      id: 'deployed_at',
      header: 'Deployed',
      sortingField: 'deployed_at',
      cell: (entry) => formatDeployedAt(entry.deployed_at),
    },
  ]
}

type SortState = { sortingField: string; isDescending: boolean }

const DEFAULT_SORT: SortState = { sortingField: 'deployed_at', isDescending: true }

export function sortChangelogRows(rows: ChangelogRow[], sort: SortState): ChangelogRow[] {
  const field = sort.sortingField as keyof ChangelogRow
  const sorted = [...rows].sort((a, b) => {
    const av = String(a[field] ?? '')
    const bv = String(b[field] ?? '')
    return av < bv ? -1 : av > bv ? 1 : 0
  })
  return sort.isDescending ? sorted.reverse() : sorted
}

/**
 * Changelog page (ENC-TSK-L33 / B67 PWA 2.0). Live changelog-API data
 * (GET /api/v1/changelog/history) rendered in a design-system-2 Table with
 * the leftmost column linking to the owning project's page.
 */
export function ChangelogRoute() {
  const { data: projects = [], isPending: projectsPending } = useQuery(projectRegistryQueryOptions)
  const projectIds = projects.map((p) => p.project_id)
  const projectNameById = new Map(projects.map((p) => [p.project_id, p.name ?? p.prefix ?? p.project_id]))

  const {
    data: entries = [],
    isPending: entriesPending,
    isError,
    error,
    refetch,
  } = useQuery(changelogHistoryQueryOptions(projectIds))

  const [sort, setSort] = useState<SortState>(DEFAULT_SORT)
  const rows = toChangelogRows(entries)
  const sortedRows = sortChangelogRows(rows, sort)

  const isPending = projectsPending || (projectIds.length > 0 && entriesPending)

  return (
    <div className="ev2-changelog">
      <Container
        header={
          <Header
            variant="h1"
            description="Live release history across every governed project — GET /api/v1/changelog/history."
          >
            Changelog
          </Header>
        }
      >
        {isError ? (
          <div className="ev2-changelog__error">
            <p>Failed to load changelog{error instanceof Error ? `: ${error.message}` : ''}.</p>
            <button type="button" onClick={() => refetch()}>
              Retry
            </button>
          </div>
        ) : (
          <Table<ChangelogRow>
            columnDefinitions={buildChangelogColumns(projectNameById)}
            items={isPending ? [] : sortedRows}
            trackBy="id"
            sortingColumn={{ sortingField: sort.sortingField }}
            sortingDescending={sort.isDescending}
            onSortingChange={(event) =>
              setSort({
                sortingField: event.detail.sortingColumn.sortingField,
                isDescending: event.detail.isDescending,
              })
            }
            empty={isPending ? 'Loading changelog…' : 'No changelog entries yet'}
          />
        )}
      </Container>
    </div>
  )
}
