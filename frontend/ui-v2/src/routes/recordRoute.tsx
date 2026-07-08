import { Suspense } from 'react'
import { useSuspenseQuery, type UseSuspenseQueryOptions } from '@tanstack/react-query'
import { createRoute, type AnyRoute } from '@tanstack/react-router'
import { queryClient } from '../api/queryClient'
import { RecordDetailBreadcrumbs } from '../components/RecordDetailBreadcrumbs'
import { SkeletonCard } from '../components/SkeletonCard'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { getPrimitive } from '../primitives/registry'
import { useRecordRealtimeSync } from '../realtime/useRecordRealtimeSync'
import type { RecordShapeMap, RecordType } from '../types/records'

type TrackerRecordType = Exclude<RecordType, 'document'>

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

  function RecordComponent() {
    const { project, id } = route.useParams() as { project: string; id: string }
    const { data } = useSuspenseQuery(queryOptionsFor(project, id))
    useRecordRealtimeSync(type, project, id)
    // ENC-TSK-M25: title derives from the resolved record (never the route
    // param alone), so it updates again once the async fetch settles — this
    // component only renders past the Suspense boundary below, i.e. after
    // `data` is available.
    useDocumentTitle(`${id}: ${data.title}`)
    const Primitive = getPrimitive(type)
    return (
      <>
        <RecordDetailBreadcrumbs recordId={id} />
        <Primitive record={data} />
      </>
    )
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
    loader: ({ params }) => {
      const { project, id } = params as { project: string; id: string }
      return queryClient.ensureQueryData(queryOptionsFor(project, id))
    },
    component: RouteComponent,
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

  function RecordComponent() {
    const { id } = route.useParams() as { id: string }
    const { data } = useSuspenseQuery(queryOptionsFor(id))
    useDocumentTitle(`${id}: ${data.title}`)
    const Primitive = getPrimitive('document')
    return (
      <>
        <RecordDetailBreadcrumbs recordId={id} />
        <Primitive record={data} />
      </>
    )
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
    loader: ({ params }) =>
      queryClient.ensureQueryData(queryOptionsFor((params as { id: string }).id)),
    component: RouteComponent,
  })

  return route
}
