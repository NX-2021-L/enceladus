import { Navigate, createBrowserRouter } from 'react-router-dom'
import { AppShell } from '../components/layout/AppShell'
import { DashboardPage } from '../pages/DashboardPage'
import { ProjectsListPage } from '../pages/ProjectsListPage'
import { ProjectDetailPage } from '../pages/ProjectDetailPage'
import { ProjectReferencePage } from '../pages/ProjectReferencePage'
import { FeedPage } from '../pages/FeedPage'
import { TaskDetailPage } from '../pages/TaskDetailPage'
import { IssueDetailPage } from '../pages/IssueDetailPage'
import { FeatureDetailPage } from '../pages/FeatureDetailPage'
import { DocumentsListPage } from '../pages/DocumentsListPage'
import { DocumentDetailPage } from '../pages/DocumentDetailPage'
import { CoordinationPage } from '../pages/CoordinationPage'
import { CoordinationDetailPage } from '../pages/CoordinationDetailPage'

const baseName = import.meta.env.BASE_URL === '/' ? undefined : import.meta.env.BASE_URL

export const router = createBrowserRouter(
  [
    {
      element: <AppShell />,
      children: [
        { path: '/', element: <DashboardPage /> },
        { path: '/projects', element: <ProjectsListPage /> },
        { path: '/projects/:projectId', element: <ProjectDetailPage /> },
        // Reference page — only reachable from ProjectDetailPage, no bottom nav entry
        { path: '/projects/:projectId/reference', element: <ProjectReferencePage /> },
        { path: '/feed', element: <FeedPage /> },
        { path: '/tasks/:taskId', element: <TaskDetailPage /> },
        { path: '/issues/:issueId', element: <IssueDetailPage /> },
        { path: '/features/:featureId', element: <FeatureDetailPage /> },
        // Redirects for old list routes (bookmarks, shared links)
        { path: '/tasks', element: <Navigate to="/feed" replace /> },
        { path: '/issues', element: <Navigate to="/feed" replace /> },
        { path: '/features', element: <Navigate to="/feed" replace /> },
        { path: '/documents', element: <DocumentsListPage /> },
        { path: '/documents/:documentId/:documentSlug', element: <DocumentDetailPage /> },
        { path: '/documents/:documentId', element: <DocumentDetailPage /> },
        { path: '/coordination', element: <CoordinationPage /> },
        { path: '/coordination/:requestId', element: <CoordinationDetailPage /> },
        // Cognito callback is handled at Lambda@Edge, but keep this as a safe fallback.
        { path: '/callback', element: <Navigate to="/" replace /> },
        { path: '*', element: <Navigate to="/" replace /> },
      ],
    },
  ],
  { basename: baseName },
)
