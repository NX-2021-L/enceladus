import { Suspense } from 'react'
import { useSuspenseQuery } from '@tanstack/react-query'
import { createRoute, type AnyRoute } from '@tanstack/react-router'
import { queryClient } from '../api/queryClient'
import { sessionQueryOptions } from '../api/sessions'
import { RecordDetailBreadcrumbs } from '../components/RecordDetailBreadcrumbs'
import { SkeletonCard } from '../components/SkeletonCard'
import { SessionPrimitive } from '../primitives/SessionPrimitive'

/**
 * Session detail route (ENC-TSK-L35 — B67 PWA2.0 session detail + worklog
 * mirroring). Path: `/session/$id`.
 *
 * Route-path convention: sessions are NOT project-scoped (ENC-SES ids are
 * globally unique, minted by coordination_api agent.register — see
 * agent_id_alloc.py SESSION_NODE_PROPERTIES), so this follows the
 * `/document/$id` pattern (createDocumentRecordRoute in recordRoute.tsx)
 * rather than the `/$project/{type}/$id` pattern the six tracker primitives
 * use. It is deliberately NOT built on top of createDocumentRecordRoute
 * itself (that helper is typed against RecordShapeMap['document'] and
 * Session is intentionally not folded into RecordShapeMap/RecordType — see
 * types/session.ts for why) — this file duplicates its loader/Suspense
 * shape instead of widening that shared generic.
 *
 * NOT WIRED INTO router.tsx: per the dispatch instructions for this task,
 * router.tsx is not edited here (7 agents are touching this PWA in
 * parallel). Add to router.tsx:
 *
 *   import { sessionRoute } from './SessionDetailRoute'
 *   // ...
 *   const routeTree = rootRoute.addChildren([
 *     ...,
 *     sessionRoute,
 *   ])
 *
 * `sessionRoute`'s `getParentRoute` below is a placeholder — replace with
 * the actual `rootRoute` reference from router.tsx when wiring in (a
 * standalone file cannot import the root route without creating a circular
 * import back into router.tsx).
 */

function SessionRecordComponent({ getParams }: { getParams: () => { id: string } }) {
  const { id } = getParams()
  const { data } = useSuspenseQuery(sessionQueryOptions(id))
  return (
    <>
      <RecordDetailBreadcrumbs recordId={id} />
      <SessionPrimitive record={data} />
    </>
  )
}

export function createSessionDetailRoute(getParentRoute: () => AnyRoute) {
  const route: AnyRoute = createRoute({
    getParentRoute,
    path: '/session/$id',
    loader: ({ params }) => {
      const { id } = params as { id: string }
      return queryClient.ensureQueryData(sessionQueryOptions(id))
    },
    component: () => (
      <Suspense fallback={<SkeletonCard label="Loading session" />}>
        <SessionRecordComponent getParams={() => route.useParams() as { id: string }} />
      </Suspense>
    ),
  })
  return route
}
