import { SearchLauncher, type SearchSuggestion } from '@io-kit/shell/react'
import type { IndexRow } from '@io-kit/search'
import type { ProjectSummary } from '../api/projects'
import { inferRecordNavigation } from '../api/projectRegistry'
import { matchActionCommands } from '../actions/commands'
import { documentHref, recordHrefForType } from '../routes/recordLink'
import { suggestRows } from '../search/corpusSource'
import './headerSearch.css'

/**
 * DVP-TSK-995 (design D13): the header "Search…" box is the kit SearchLauncher. A 44px magnifier at every width plus
 * Cmd/Ctrl-K opens a sheet with one input; instant suggestions come from the local corpus index (and a record-id jump
 * and the registry action commands the old palette offered); Enter or "See all results" routes to /feed?q=.
 */
export function buildHeaderSuggestions(text: string, rows: readonly IndexRow[], projects: ProjectSummary[]): SearchSuggestion[] {
  const out: SearchSuggestion[] = []
  const nav = inferRecordNavigation(text, projects)
  if (nav) {
    const href = nav.type === 'document' ? documentHref(nav.id) : nav.projectId ? recordHrefForType(nav.projectId, nav.type, nav.id) : null
    if (href) out.push({ id: `jump:${nav.id}`, title: `Open ${nav.id}`, recordId: nav.id, kind: nav.type, href })
  }
  for (const row of suggestRows(rows, text, 8)) {
    const project = typeof row.fields.project_id === 'string' ? row.fields.project_id : 'enceladus'
    const href = row.type === 'document' ? documentHref(row.id) : recordHrefForType(project, row.type as never, row.id)
    // DVP-TSK-B11: structured meta, so the id renders like .enc-record-id (mono accent) and the type in dim mono.
    out.push({ id: row.id, title: row.title || row.id, recordId: row.id, kind: row.type, href })
  }
  for (const c of matchActionCommands(text).slice(0, 3)) {
    out.push({ id: `action:${c.name}`, title: c.name, subtitle: c.title, href: `/actions/${c.name}` })
  }
  return out
}

export function HeaderSearch({
  rows,
  projects,
  onNavigate,
}: {
  rows: readonly IndexRow[]
  projects: ProjectSummary[]
  onNavigate: (href: string) => void
}) {
  return (
    <SearchLauncher
      to="/feed"
      label="Search"
      placeholder="Search records"
      suggest={async (text) => buildHeaderSuggestions(text, rows, projects)}
      onNavigate={onNavigate}
    />
  )
}
