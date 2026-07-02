import { Suspense } from 'react'
import { useSuspenseQuery, type UseSuspenseQueryOptions } from '@tanstack/react-query'
import { createRoute, type AnyRoute } from '@tanstack/react-router'
import { queryClient } from '../api/queryClient'
import { SkeletonCard } from '../components/SkeletonCard'
import { getPrimitive } from '../primitives/registry'
import type { RecordShapeMap, RecordType } from '../types/records'

/**
 * Builds one record-detail route for a given record type (AC-14). Each route:
 *
 *   1. `loader` calls queryClient.ensureQueryData(queryOptions) so the data is
 *      primed before render (no client-side loading waterfall).
 *   2. The component calls useSuspenseQuery(queryOptions) — `data` is typed
 *      RecordShapeMap[K] (never `... | undefined`). There are ZERO `isLoading`
 *      branches and ZERO `data?.` optional chaining here.
 *   3. A route-level <Suspense fallback={<SkeletonCard />}> boundary wraps the
 *      component, so first paint shows the skeleton, not a spinner-in-content.
 *
 * The concrete queryOptions factory is injected per type, keeping the six route
 * modules thin while the loader/suspense contract lives in exactly one place.
 */
export function createRecordRoute<K extends RecordType>(config: {
  getParentRoute: () => AnyRoute
  path: string
  type: K
  queryOptionsFor: (id: string) => UseSuspenseQueryOptions<RecordShapeMap[K]>
}) {
  const { getParentRoute, path, type, queryOptionsFor } = config

  function RecordComponent() {
    const { id } = route.useParams()
    // useSuspenseQuery -> data is RecordShapeMap[K], fully typed, never undefined.
    const { data } = useSuspenseQuery(queryOptionsFor(id))
    const Primitive = getPrimitive(type)
    return <Primitive record={data} />
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
    loader: ({ params }) =>
      queryClient.ensureQueryData(queryOptionsFor((params as { id: string }).id)),
    component: RouteComponent,
  })

  return route
}
