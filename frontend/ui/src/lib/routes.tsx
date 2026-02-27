import { lazy, Suspense } from 'react'
import type { ReactNode } from 'react'
import { Navigate, createBrowserRouter } from 'react-router-dom'
import { AppShell } from '../components/layout/AppShell'
import { LoadingState } from '../components/shared/LoadingState'

const DashboardPage = lazy(() =>
  import('../pages/DashboardPage').then((module) => ({ default: module.DashboardPage })),
)
const ProjectsListPage = lazy(() =>
  import('../pages/ProjectsListPage').then((module) => ({ default: module.ProjectsListPage })),
)
const ProjectDetailPage = lazy(() =>
  import('../pages/ProjectDetailPage').then((module) => ({ default: module.ProjectDetailPage })),
)
const ProjectReferencePage = lazy(() =>
  import('../pages/ProjectReferencePage').then((module) => ({
    default: module.ProjectReferencePage,
  })),
)
const CreateProjectPage = lazy(() =>
  import('../pages/CreateProjectPage').then((module) => ({ default: module.CreateProjectPage })),
)
const FeedPage = lazy(() =>
  import('../pages/FeedPage').then((module) => ({ default: module.FeedPage })),
)
const TaskDetailPage = lazy(() =>
  import('../pages/TaskDetailPage').then((module) => ({ default: module.TaskDetailPage })),
)
const IssueDetailPage = lazy(() =>
  import('../pages/IssueDetailPage').then((module) => ({ default: module.IssueDetailPage })),
)
const FeatureDetailPage = lazy(() =>
  import('../pages/FeatureDetailPage').then((module) => ({ default: module.FeatureDetailPage })),
)
const DocumentsListPage = lazy(() =>
  import('../pages/DocumentsListPage').then((module) => ({ default: module.DocumentsListPage })),
)
const DocumentDetailPage = lazy(() =>
  import('../pages/DocumentDetailPage').then((module) => ({
    default: module.DocumentDetailPage,
  })),
)
const CoordinationPage = lazy(() =>
  import('../pages/CoordinationPage').then((module) => ({ default: module.CoordinationPage })),
)
const CoordinationDetailPage = lazy(() =>
  import('../pages/CoordinationDetailPage').then((module) => ({
    default: module.CoordinationDetailPage,
  })),
)
const AuthTokensPage = lazy(() =>
  import('../pages/AuthTokensPage').then((module) => ({ default: module.AuthTokensPage })),
)

function withSuspense(element: ReactNode) {
  return <Suspense fallback={<LoadingState />}>{element}</Suspense>
}

const baseName = import.meta.env.BASE_URL === '/' ? undefined : import.meta.env.BASE_URL

export const router = createBrowserRouter(
  [
    {
      element: <AppShell />,
      children: [
        { path: '/', element: withSuspense(<DashboardPage />) },
        { path: '/projects', element: withSuspense(<ProjectsListPage />) },
        { path: '/projects/create', element: withSuspense(<CreateProjectPage />) },
        { path: '/projects/:projectId', element: withSuspense(<ProjectDetailPage />) },
        // Reference page — only reachable from ProjectDetailPage, no bottom nav entry
        {
          path: '/projects/:projectId/reference',
          element: withSuspense(<ProjectReferencePage />),
        },
        { path: '/feed', element: withSuspense(<FeedPage />) },
        { path: '/tasks/:taskId', element: withSuspense(<TaskDetailPage />) },
        { path: '/issues/:issueId', element: withSuspense(<IssueDetailPage />) },
        { path: '/features/:featureId', element: withSuspense(<FeatureDetailPage />) },
        // Redirects for old list routes (bookmarks, shared links)
        { path: '/tasks', element: <Navigate to="/feed" replace /> },
        { path: '/issues', element: <Navigate to="/feed" replace /> },
        { path: '/features', element: <Navigate to="/feed" replace /> },
        { path: '/documents', element: withSuspense(<DocumentsListPage />) },
        {
          path: '/documents/:documentId/:documentSlug',
          element: withSuspense(<DocumentDetailPage />),
        },
        { path: '/documents/:documentId', element: withSuspense(<DocumentDetailPage />) },
        { path: '/coordination', element: withSuspense(<CoordinationPage />) },
        { path: '/coordination/auth', element: withSuspense(<AuthTokensPage />) },
        {
          path: '/coordination/:requestId',
          element: withSuspense(<CoordinationDetailPage />),
        },
        // Cognito callback is handled at Lambda@Edge, but keep this as a safe fallback.
        { path: '/callback', element: <Navigate to="/" replace /> },
        { path: '*', element: <Navigate to="/" replace /> },
      ],
    },
  ],
  { basename: baseName },
)
