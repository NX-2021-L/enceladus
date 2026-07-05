import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from '@tanstack/react-router'
import { AppShell } from '../shell/AppShell'
import { FeedRoute } from './FeedRoute'
import { HomeRoute } from './HomeRoute'
import { PlaceholderRoute } from './PlaceholderRoute'
import { ProjectsRoute } from './ProjectsRoute'
import { DocsRoute } from './DocsRoute'
import { ChangelogRoute } from './ChangelogRoute'
import { CoordinationRoute } from './CoordinationRoute'
import { createSessionDetailRoute } from './SessionDetailRoute'
import { createAgentDetailRoute } from './AgentDetailRoute'
import { parseFeedSearch } from '../search/feedSearchParams'
import { createDocumentRecordRoute, createRecordRoute } from './recordRoute'
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
  path: '/$project/task/$id',
  type: 'task',
  queryOptionsFor: taskQueryOptions,
})
const issueRoute = createRecordRoute({
  getParentRoute: () => rootRoute,
  path: '/$project/issue/$id',
  type: 'issue',
  queryOptionsFor: issueQueryOptions,
})
const featureRoute = createRecordRoute({
  getParentRoute: () => rootRoute,
  path: '/$project/feature/$id',
  type: 'feature',
  queryOptionsFor: featureQueryOptions,
})
const planRoute = createRecordRoute({
  getParentRoute: () => rootRoute,
  path: '/$project/plan/$id',
  type: 'plan',
  queryOptionsFor: planQueryOptions,
})
const lessonRoute = createRecordRoute({
  getParentRoute: () => rootRoute,
  path: '/$project/lesson/$id',
  type: 'lesson',
  queryOptionsFor: lessonQueryOptions,
})
const documentRoute = createDocumentRecordRoute({
  getParentRoute: () => rootRoute,
  path: '/document/$id',
  queryOptionsFor: documentQueryOptions,
})

const feedRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/feed',
  validateSearch: parseFeedSearch,
  component: FeedRoute,
})

const projectsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/projects',
  component: ProjectsRoute,
})
const docsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/docs',
  component: DocsRoute,
})
const changelogRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/changelog',
  component: ChangelogRoute,
})
const coordinationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/coordination',
  component: CoordinationRoute,
})
const sessionRoute = createSessionDetailRoute(() => rootRoute)
const agentDetailRoute = createAgentDetailRoute({ getParentRoute: () => rootRoute })

// Remaining shell nav placeholders not yet built out (component registry,
// deployment manager, access tokens, terminal sessions).
const shellNavRoutes = [
  { path: '/component-registry', title: 'Component registry' },
  { path: '/deployments', title: 'Deployment manager' },
  { path: '/access-tokens', title: 'Access tokens' },
  { path: '/terminal-sessions', title: 'Terminal sessions' },
] as const

const placeholderRoutes = shellNavRoutes.map(({ path, title }) =>
  createRoute({
    getParentRoute: () => rootRoute,
    path,
    component: () => <PlaceholderRoute title={title} />,
  }),
)

const routeTree = rootRoute.addChildren([
  indexRoute,
  feedRoute,
  projectsRoute,
  docsRoute,
  changelogRoute,
  coordinationRoute,
  sessionRoute,
  agentDetailRoute,
  ...placeholderRoutes,
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
