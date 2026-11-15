/**
 * Component registry, read surface (ENC-TSK-S81 / ENC-PLN-107). No write control.
 * /component-registry: list. /component-registry/$componentId: detail.
 * State: records live in TanStack Query; useState holds view state only.
 */
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from '@tanstack/react-router'
import { getComponent, listComponents, type RegistryComponent } from '../api/components'
import { Alert, Button, KeyValuePairs } from '../design-system'
import { PageHeader } from '../components/PageHeader'
import { Table } from '../components/StackedTable'
import { Tag } from '../components/Pill'
import { StatusPill } from '../components/StatusPill'
import { CopyIdButton } from '../components/CopyIdButton'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import {
  FLOOR_LADDER, floorView, inSegment, isGoverned, matchesText, registryRows, segmentCounts, sortRows,
  type RegistrySegment, type SortField,
} from './componentRegistry'
import './componentRegistry.css'

const PAGE = 25
const SEGMENTS: { id: RegistrySegment; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'pipeline', label: 'In pipeline' },
  { id: 'production', label: 'Production' },
  { id: 'none', label: 'No lifecycle' },
  { id: 'legacy', label: 'Legacy disagrees' },
]

function LifecyclePill({ value }: { value: string | undefined }) {
  if (!value) return <span className="ev2-reg__none">none</span>
  // StatusPill resolves the role from status-map.json; a value outside the governed eight renders verbatim (unknown role).
  return <StatusPill status={value} kind="component_lifecycle" />
}

function Floor({ c }: { c: RegistryComponent }) {
  const f = floorView(c)
  if (!f.cls) return <span className="ev2-reg__none">none</span>
  return (
    <span className="ev2-reg__floor">
      <Tag>{f.cls}</Tag>
      {f.showStored && <span className="ev2-reg__stored">stored as {f.stored}</span>}
    </span>
  )
}

export function ComponentRegistryRoute() {
  useDocumentTitle('Component registry')
  const [q, setQ] = useState('')
  const [seg, setSeg] = useState<RegistrySegment>('all')
  const [sortField, setSortField] = useState<SortField>('updated_at')
  const [desc, setDesc] = useState(true)
  const [limit, setLimit] = useState(PAGE)
  const query = useQuery({ queryKey: ['component-registry'], queryFn: ({ signal }) => listComponents({ signal }) })

  const rows = registryRows(query.data ?? [])
  const counts = segmentCounts(rows)
  const visible = sortRows(rows.filter((c) => inSegment(c, seg) && matchesText(c, q)), sortField, desc)
  const shown = visible.slice(0, limit)

  const columns = [
    {
      id: 'component', header: 'Component', sortingField: 'component_id',
      cell: (c: RegistryComponent) => (
        <span className="ev2-reg__comp">
          <Link to="/component-registry/$componentId" params={{ componentId: c.component_id }} className="ev2-reg__id">{c.component_id}</Link>
          <span className="ev2-reg__name">{c.component_name}</span>
        </span>
      ),
    },
    { id: 'project', header: 'Project', sortingField: 'project_id', cell: (c: RegistryComponent) => <Tag code>{c.project_id}</Tag> },
    { id: 'category', header: 'Category', sortingField: 'category', cell: (c: RegistryComponent) => <Tag>{c.category}</Tag> },
    { id: 'lifecycle', header: 'Lifecycle', sortingField: 'lifecycle_status', cell: (c: RegistryComponent) => <LifecyclePill value={c.lifecycle_status} /> },
    { id: 'floor', header: 'Floor', cell: (c: RegistryComponent) => <Floor c={c} /> },
    { id: 'updated', header: 'Updated', sortingField: 'updated_at', cell: (c: RegistryComponent) => (c.updated_at ?? '').slice(0, 10) || 'none' },
  ]

  return (
    <div className="ev2-page">
      <PageHeader
        title="Component registry"
        count={query.isPending ? undefined : rows.length}
        description="The governed components every task is checked out against. Read only."
      />
      {query.isError && (
        <Alert type="error" header="Could not load the component registry">
          {query.error instanceof Error ? query.error.message : 'Unknown error'}
        </Alert>
      )}
      <input
        className="ev2-reg__search" type="search" value={q} aria-label="Search components"
        placeholder="Search by name, ID or project"
        onChange={(e) => { setQ(e.target.value); setLimit(PAGE) }}
      />
      <div className="ev2-reg__segments" role="group" aria-label="Lifecycle segments">
        {SEGMENTS.map((s) => (
          <button
            key={s.id} type="button" className="ev2-reg__seg" aria-pressed={seg === s.id}
            onClick={() => { setSeg(s.id); setLimit(PAGE) }}
          >
            {s.label} <span className="ev2-reg__segcount">{counts[s.id]}</span>
          </button>
        ))}
      </div>
      <Table
        columnDefinitions={columns}
        items={query.isPending ? [] : shown}
        trackBy="component_id"
        empty={query.isPending ? 'Loading components…' : 'No components match.'}
        sortingColumn={{ sortingField: sortField }}
        sortingDescending={desc}
        onSortingChange={({ detail }: { detail: { sortingColumn: { sortingField: string }; isDescending: boolean } }) => {
          setSortField(detail.sortingColumn.sortingField as SortField)
          setDesc(detail.isDescending)
        }}
      />
      {visible.length > shown.length && (
        <div className="ev2-reg__more">
          <Button variant="normal" onClick={() => setLimit(limit + PAGE)}>Show more ({visible.length - shown.length} left)</Button>
        </div>
      )}
    </div>
  )
}

function NotFound({ id }: { id: string }) {
  return (
    <div className="ev2-page">
      <PageHeader title="Component not found" />
      <Alert type="warning" header={`${id} was not found`}>
        It does not exist or has been archived. <Link to="/component-registry">Back to the registry</Link>
      </Alert>
    </div>
  )
}

export function ComponentDetailRoute() {
  const { componentId = '' } = useParams({ strict: false }) as { componentId?: string }
  useDocumentTitle(componentId || 'Component')
  const query = useQuery({
    queryKey: ['component-registry', componentId],
    queryFn: ({ signal }) => getComponent(componentId, { signal }),
    retry: false,
  })
  if (query.isPending) return <div className="ev2-page"><PageHeader title={componentId} /><p>Loading…</p></div>
  const c = query.data
  const archived = c && (c.status === 'archived' || c.lifecycle_status === 'archived')
  if (query.isError || !c || archived) return <NotFound id={componentId} />

  const f = floorView(c)
  const facts = [
    { label: 'Project', value: c.project_id },
    { label: 'Category', value: c.category },
    { label: 'Status', value: c.status ?? 'none' },
    { label: 'Transition type', value: c.transition_type ?? 'none', mono: true },
    { label: 'Required transition type', value: c.required_transition_type ?? 'none', mono: true },
    { label: 'GitHub repo', value: c.github_repo ?? 'none' },
    { label: 'Created', value: c.created_at ?? 'none' },
    { label: 'Updated', value: c.updated_at ?? 'none' },
    ...(c.approved_at ? [{ label: 'Approved', value: `${c.approved_at}${c.approved_by ? ` by ${c.approved_by}` : ''}` }] : []),
    ...(c.deprecated_at ? [{ label: 'Deprecated', value: `${c.deprecated_at}${c.deprecated_reason ? `: ${c.deprecated_reason}` : ''}` }] : []),
  ]
  return (
    <div className="ev2-page">
      <PageHeader title={c.component_name} />
      <div className="ev2-reg__detailhead">
        <span className="ev2-reg__id">{c.component_id}</span>
        <CopyIdButton id={c.component_id} />
        <LifecyclePill value={c.lifecycle_status} />
        {!isGoverned(c.lifecycle_status) && c.lifecycle_status && <span className="ev2-reg__stored">not a governed status</span>}
      </div>
      <section className="ev2-reg__section">
        <h2 className="ev2-reg__h2">Floor ladder</h2>
        <ol className="ev2-reg__ladder">
          {FLOOR_LADDER.map((cls, rank) => (
            <li key={cls} className="ev2-reg__rung" aria-current={f.cls === cls ? 'true' : undefined}>
              <span className="ev2-reg__rank">{rank}</span> {cls}
            </li>
          ))}
        </ol>
        {f.showStored && <div className="ev2-reg__stored">stored as {f.stored}</div>}
      </section>
      <section className="ev2-reg__section"><KeyValuePairs items={facts} columns={2} /></section>
      {c.description && <section className="ev2-reg__section"><h2 className="ev2-reg__h2">Description</h2><p className="ev2-reg__desc">{c.description}</p></section>}
      <Link to="/component-registry" className="ev2-reg__back">Back to the registry</Link>
    </div>
  )
}
