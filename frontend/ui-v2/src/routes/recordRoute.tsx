import { Suspense } from 'react'
import { useSuspenseQuery, type UseSuspenseQueryOptions } from '@tanstack/react-query'
import { createRoute, Link, useParams, type AnyRoute } from '@tanstack/react-router'
import { NotFoundError } from '../api/client'
import { queryClient } from '../api/queryClient'
import { RecordDetailBreadcrumbs } from '../components/RecordDetailBreadcrumbs'
import { SkeletonCard } from '../components/SkeletonCard'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { getPrimitive } from '../primitives/registry'
import { useRecordRealtimeSync } from '../realtime/useRecordRealtimeSync'
import type { RecordShapeMap, RecordType } from '../types/records'
import './recordNotFound.css'

type TrackerRecordType = Exclude<RecordType, 'document'>

/**
 * ENC-TSK-P58 (ENC-ISS-713) — in-shell "record not found" state.
 *
 * Registered as `errorComponent` on every record-detail route so a 404 from
 * the record loader renders INSIDE the app shell (sidebar/header intact)
 * instead of escaping to the root error boundary and taking the whole UI
 * down. Any non-404 error is rethrown and still reaches the global boundary.
 */
export function RecordNotFoundPanel({ recordId }: { recordId: string }) {
  useDocumentTitle('Record not found')
  return (
    <div className="ev2-record-notfound" role="alert">
      <p className="ev2-record-notfound__eyebrow">RECORD NOT FOUND</p>
      <h1 className="ev2-record-notfound__title">
        <span className="ev2-record-notfound__id">{recordId || 'This record'}</span> isn&apos;t here
      </h1>
      <p className="ev2-record-notfound__body">
        The id doesn&apos;t match a record of this type — it may use a different type segment, live
        in another project, or not exist. Check the id, or start from a search surface:
      </p>
      <nav className="ev2-record-notfound__links" aria-label="Record not found suggestions">
        <Link to="/feed">Search the Feed</Link>
        <Link to="/docs">Search Documents</Link>
      </nav>
    </div>
  )
}

function RecordRouteError({ error }: { error: Error }) {
  const params = useParams({ strict: false }) as { id?: string }
  if (!(error instanceof NotFoundError)) throw error
  return <RecordNotFoundPanel recordId={params.id ?? ''} />
}

/**
 * ENC-TSK-P58 verification fix (ENC-ISS-713): a loader that THROWS during the
 * router's very first load left the page permanently blank on a cold load of
 * a not-found URL (the error never reached the route-level errorComponent).
 * The loader now resolves to this sentinel instead of throwing for a 404, and
 * the component renders the in-shell panel for it — no error-boundary
 * semantics involved on the happy 404 path. The errorComponent stays as the
 * backstop for errors thrown later (e.g. useSuspenseQuery on a record deleted
 * mid-view).
 */
export const RECORD_NOT_FOUND = { __recordNotFound: true } as const

export function isRecordNotFound(value: unknown): value is typeof RECORD_NOT_FOUND {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as { __recordNotFound?: boolean }).__recordNotFound === true
  )
}

/**
 * Builds one tracker record-detail route for a given record type (AC-14). Each route:
 *
 *   1. `loader` calls queryClient.ensureQueryData(queryOptions) so the data is
 *      primed before render (no client-side loading waterfall).
 *   2. The component calls useSuspenseQuery(queryOptions) — `data` is typed
 *      RecordShapeMap[K] (never `... | undefined`). There are ZERO `isLoading`
 *      branches and ZERO `data?.` optional chaining here.
 *   3. A route-level <Suspense fallback={<SkeletonCard />}> boundary wraps the
 *      component, so first paint shows the skeleton, not a spinner-in-content.
 */
export function createRecordRoute<K extends TrackerRecordType>(config: {
  getParentRoute: () => AnyRoute
  path: string
  type: K
  queryOptionsFor: (
    projectId: string,
    id: string,
  ) => UseSuspenseQueryOptions<RecordShapeMap[K]>
}) {
  const { getParentRoute, path, type, queryOptionsFor } = config
  const Primitive = getPrimitive(type)

  function RecordBody({ project, id }: { project: string; id: string }) {
    const { data } = useSuspenseQuery(queryOptionsFor(project, id))
    useRecordRealtimeSync(type, project, id)
    // ENC-TSK-M25: title derives from the resolved record (never the route
    // param alone), so it updates again once the async fetch settles — this
    // component only renders past the Suspense boundary below, i.e. after
    // `data` is available.
    useDocumentTitle(`${id}: ${data.title}`)
    return (
      <>
        <RecordDetailBreadcrumbs recordId={id} />
        <Primitive record={data} />
      </>
    )
  }

  function RecordComponent() {
    const { project, id } = route.useParams() as { project: string; id: string }
    const loaderData = route.useLoaderData()
    // Constant hook count here — the not-found branch renders a different
    // CHILD, never a different number of hooks in this component.
    if (isRecordNotFound(loaderData)) return <RecordNotFoundPanel recordId={id} />
    return <RecordBody project={project} id={id} />
  }

  function RouteComponent() {
    return (
      <Suspense fallback={<SkeletonCard label={`Loading ${type}`} />}>
        <RecordComponent />
      </Suspense>
    )
  }

  const route: AnyRoute = createRoute({
    getParentRoute,
    path,
    loader: async ({ params }) => {
      const { project, id } = params as { project: string; id: string }
      try {
        return await queryClient.ensureQueryData(queryOptionsFor(project, id))
      } catch (error) {
        if (error instanceof NotFoundError) return RECORD_NOT_FOUND
        throw error
      }
    },
    component: RouteComponent,
    errorComponent: RecordRouteError,
  })

  return route
}

/** Document routes omit project slug — docstore ids are globally unique. */
export function createDocumentRecordRoute(config: {
  getParentRoute: () => AnyRoute
  path: string
  queryOptionsFor: (id: string) => UseSuspenseQueryOptions<RecordShapeMap['document']>
}) {
  const { getParentRoute, path, queryOptionsFor } = config
  const Primitive = getPrimitive('document')

  function RecordBody({ id }: { id: string }) {
    const { data } = useSuspenseQuery(queryOptionsFor(id))
    useDocumentTitle(`${id}: ${data.title}`)
    return (
      <>
        <RecordDetailBreadcrumbs recordId={id} />
        <Primitive record={data} />
      </>
    )
  }

  function RecordComponent() {
    const { id } = route.useParams() as { id: string }
    const loaderData = route.useLoaderData()
    // Constant hook count — the not-found branch renders a different child,
    // never a different number of hooks in this component.
    if (isRecordNotFound(loaderData)) return <RecordNotFoundPanel recordId={id} />
    return <RecordBody id={id} />
  }

  function RouteComponent() {
    return (
      <Suspense fallback={<SkeletonCard label="Loading document" />}>
        <RecordComponent />
      </Suspense>
    )
  }

  const route: AnyRoute = createRoute({
    getParentRoute,
    path,
    loader: async ({ params }) => {
      try {
        return await queryClient.ensureQueryData(queryOptionsFor((params as { id: string }).id))
      } catch (error) {
        if (error instanceof NotFoundError) return RECORD_NOT_FOUND
        throw error
      }
    },
    component: RouteComponent,
    errorComponent: RecordRouteError,
  })

  return route
}
