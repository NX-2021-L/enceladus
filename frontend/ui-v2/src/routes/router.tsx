import {
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
  Outlet,
} from '@tanstack/react-router'
import { AppShell } from '../shell/AppShell'
import { HomeRoute } from './HomeRoute'
import { PlaceholderRoute } from './PlaceholderRoute'
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

// ENC-TSK-M18 (perf budget, AC-2): every non-Home top-level route is
// code-split via lazyRouteComponent so the initial "/" bundle (mobile
// default route) doesn't pay for Feed/Projects/Docs/Governance/Changelog/
// Coordination/SkillLibrary JS it doesn't need. `parseFeedSearch` stays a
// static import — it's a tiny pure function needed to validate the URL
// before the Feed chunk loads, not the Feed UI itself.
const feedRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/feed',
  validateSearch: parseFeedSearch,
  component: lazyRouteComponent(() => import('./FeedRoute'), 'FeedRoute'),
})

const projectsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/projects',
  component: lazyRouteComponent(() => import('./ProjectsRoute'), 'ProjectsRoute'),
})
const docsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/docs',
  component: lazyRouteComponent(() => import('./DocsRoute'), 'DocsRoute'),
})
const governanceRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/governance',
  component: lazyRouteComponent(() => import('./GovernanceRoute'), 'GovernanceRoute'),
})
const changelogRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/changelog',
  component: lazyRouteComponent(() => import('./ChangelogRoute'), 'ChangelogRoute'),
})
const coordinationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/coordination',
  // ENC-TSK-M19: lets Home's "Requires io" queue deep-link an escalation row
  // straight to the Escalations tab (?tab=escalations) instead of landing on
  // the default Sessions tab.
  validateSearch: (raw: Record<string, unknown>) => ({
    tab: typeof raw.tab === 'string' ? raw.tab : '',
  }),
  component: lazyRouteComponent(() => import('./CoordinationRoute'), 'CoordinationRoute'),
})
const skillLibraryRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/skills',
  component: lazyRouteComponent(() => import('./SkillLibraryRoute'), 'SkillLibraryRoute'),
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
  governanceRoute,
  changelogRoute,
  coordinationRoute,
  skillLibraryRoute,
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
