import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { Container, Header, Table } from '../design-system'
import type { TableColumnDefinition } from '../../../design-system-2/v2/components/Table/Table'
import { skillLibraryQueryOptions, type SkillListItem } from '../api/skillLibrary'
import { documentHref } from './recordLink'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import './skillLibrary.css'

/**
 * The skill catalog is scoped to the `enceladus` project (ENC-TSK-L93/L94):
 * the source projection endpoint, docstore skill records, and this task's
 * ACs are all enceladus-specific. Deliberately NOT derived from
 * `projects[0]` (project registry order is not guaranteed to put enceladus
 * first — verified live during gamma validation, where it resolved to a
 * different project and silently returned zero rows).
 */
const SKILL_LIBRARY_PROJECT_ID = 'enceladus'

function formatUpdatedAt(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value || '—'
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function buildSkillLibraryColumns(): TableColumnDefinition<SkillListItem>[] {
  return [
    {
      id: 'title',
      header: 'Skill',
      sortingField: 'title',
      cell: (item) => (
        <Link to={documentHref(item.document_id)} className="ev2-skill-library__title-link">
          {item.title || item.document_id}
        </Link>
      ),
    },
    {
      id: 'description',
      header: 'Description',
      cell: (item) => (item.description?.trim() ? item.description : '—'),
    },
    {
      id: 'version',
      header: 'Version',
      sortingField: 'version',
      cell: (item) => <span className="ev2-table__mono">{item.version || '—'}</span>,
    },
    {
      id: 'runtime_hint',
      header: 'Runtime',
      cell: (item) => item.runtime_hint || '—',
    },
    {
      id: 'updated_at',
      header: 'Updated',
      sortingField: 'updated_at',
      cell: (item) => formatUpdatedAt(item.updated_at),
    },
  ]
}

type SortState = { sortingField: string; isDescending: boolean }

// ENC-TSK-N57 (ENC-TSK-N45/N56 UAT follow-up): the Skill Library table defaults
// to most-recently-updated first on initial load, matching the N45 intent that
// every feed defaults to time-last-updated, newest to oldest. updated_at is an
// ISO-8601 string, so sortSkillLibraryRows' lexicographic compare + reverse is a
// correct chronological descending sort (blank timestamps sort last). The
// click-to-toggle asc/desc behavior on any column header (onSortingChange) is
// preserved untouched for user-initiated re-sorts.
export const DEFAULT_SORT: SortState = { sortingField: 'updated_at', isDescending: true }

export function sortSkillLibraryRows(rows: SkillListItem[], sort: SortState): SkillListItem[] {
  const field = sort.sortingField as keyof SkillListItem
  const sorted = [...rows].sort((a, b) => {
    const av = String(a[field] ?? '')
    const bv = String(b[field] ?? '')
    return av < bv ? -1 : av > bv ? 1 : 0
  })
  return sort.isDescending ? sorted.reverse() : sorted
}

/**
 * Skill Library page (ENC-TSK-L94 / FTR-129). Every document_subtype=skill
 * record, eagerly loaded (no pagination, no lazy load — AC-1) from the
 * body-excluded metadata projection (ENC-TSK-L93: GET /api/v1/documents
 * ?document_subtype=skill&include_content=false) resolved fresh on mount
 * (AC-2). Each row links to the existing document detail route (AC-3). The
 * ftr-078-e2e-skill test fixture is excluded by default — see
 * src/api/skillLibrary.ts for the AC-4 rationale.
 */
export function SkillLibraryRoute() {
  useDocumentTitle('Skill Library')
  const {
    data: items = [],
    isPending,
    isError,
    error,
    refetch,
  } = useQuery(skillLibraryQueryOptions(SKILL_LIBRARY_PROJECT_ID))

  const [sort, setSort] = useState<SortState>(DEFAULT_SORT)
  const sortedRows = sortSkillLibraryRows(items, sort)

  return (
    <div className="ev2-skill-library">
      <Container
        header={
          <Header
            variant="h1"
            description="Every governed skill record — resolved fresh from the body-excluded metadata projection on each page load. No client-side catalog or cache of the list."
          >
            Skill Library
          </Header>
        }
      >
        {isError ? (
          <div className="ev2-skill-library__error">
            <p>Failed to load skill library{error instanceof Error ? `: ${error.message}` : ''}.</p>
            <button type="button" onClick={() => refetch()}>
              Retry
            </button>
          </div>
        ) : (
          <Table<SkillListItem>
            columnDefinitions={buildSkillLibraryColumns()}
            items={isPending ? [] : sortedRows}
            trackBy="document_id"
            sortingColumn={{ sortingField: sort.sortingField }}
            sortingDescending={sort.isDescending}
            onSortingChange={(event) =>
              setSort({
                sortingField: event.detail.sortingColumn.sortingField,
                isDescending: event.detail.isDescending,
              })
            }
            empty={isPending ? 'Loading skill library…' : 'No skills found.'}
          />
        )}
      </Container>
    </div>
  )
}
