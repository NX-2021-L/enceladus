import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from '@tanstack/react-router'
import { AppShell } from '../shell/AppShell'
import { HomeRoute } from './HomeRoute'
import { createRecordRoute } from './recordRoute'
import {
  documentQueryOptions,
  featureQueryOptions,
  issueQueryOptions,
  lessonQueryOptions,
  planQueryOptions,
  taskQueryOptions,
} from '../api/queryOptions'

const rootRoute = createRootRoute({
  component: () => (
    <AppShell>
      <Outlet />
    </AppShell>
  ),
})

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: HomeRoute,
})

// AC-14 — six real record-detail routes, each with the loader + useSuspenseQuery
// + route-level Suspense contract enforced by createRecordRoute.
const taskRoute = createRecordRoute({
  getParentRoute: () => rootRoute,
  path: '/task/$id',
  type: 'task',
  queryOptionsFor: taskQueryOptions,
})
const issueRoute = createRecordRoute({
  getParentRoute: () => rootRoute,
  path: '/issue/$id',
  type: 'issue',
  queryOptionsFor: issueQueryOptions,
})
const featureRoute = createRecordRoute({
  getParentRoute: () => rootRoute,
  path: '/feature/$id',
  type: 'feature',
  queryOptionsFor: featureQueryOptions,
})
const planRoute = createRecordRoute({
  getParentRoute: () => rootRoute,
  path: '/plan/$id',
  type: 'plan',
  queryOptionsFor: planQueryOptions,
})
const lessonRoute = createRecordRoute({
  getParentRoute: () => rootRoute,
  path: '/lesson/$id',
  type: 'lesson',
  queryOptionsFor: lessonQueryOptions,
})
const documentRoute = createRecordRoute({
  getParentRoute: () => rootRoute,
  path: '/document/$id',
  type: 'document',
  queryOptionsFor: documentQueryOptions,
})

const routeTree = rootRoute.addChildren([
  indexRoute,
  taskRoute,
  issueRoute,
  featureRoute,
  planRoute,
  lessonRoute,
  documentRoute,
])

export const router = createRouter({
  routeTree,
  defaultPreload: 'intent',
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
