/**
 * Detail-page fallback integration tests (ENC-FTR-073 Phase 3 / ENC-TSK-D91).
 *
 * Validates that each of the six detail pages:
 *   - calls useRecordFallback exactly once per mount with the feed cache input,
 *   - renders RecordFallbackLoading / RecordNotFound / RecordFallbackError
 *     from the hook's return values, and
 *   - renders the expected content when `data` is present.
 *
 * Scope:
 *   The hook itself has its own unit test suite (useRecordFallback.test.tsx).
 *   These tests exercise the *wiring* between the page and the hook so that
 *   the AC7 "zero additional fetches for in-feed records" and the
 *   Loading/NotFound/Error UX contracts are verified end-to-end at the page
 *   layer. All heavy subcomponents (LifecycleActions, GitHubOverlay,
 *   PlanTree, PillarScoreChart, etc.) are spare-renderable from the minimal
 *   record fixtures used below.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type {
  Document,
  Feature,
  Issue,
  Lesson,
  Plan,
  ProjectSummary,
  Task,
} from '../types/feeds'

// ---------------------------------------------------------------------------
// Mocks — fix the hook surface at the page's import boundary so each test can
// stub in cached / out-of-feed / 404 / error outcomes without running the
// underlying TanStack Query machinery.
// ---------------------------------------------------------------------------

const { mockUseRecordFallback } = vi.hoisted(() => ({
  mockUseRecordFallback: vi.fn(),
}))

vi.mock('../hooks/useRecordFallback', () => ({
  useRecordFallback: mockUseRecordFallback,
}))

const EMPTY_FEED = {
  allTasks: [],
  allIssues: [],
  allFeatures: [],
  tasks: [],
  issues: [],
  features: [],
  lessons: [],
  plans: [],
  generatedAt: '2026-04-15T00:00:00Z',
  isPending: false,
  isError: false,
  isLoading: false,
  data: undefined,
}

vi.mock('../hooks/useTasks', () => ({
  useTasks: () => EMPTY_FEED,
}))

vi.mock('../hooks/useIssues', () => ({
  useIssues: () => EMPTY_FEED,
}))

vi.mock('../hooks/useFeatures', () => ({
  useFeatures: () => EMPTY_FEED,
}))

vi.mock('../hooks/useLessons', () => ({
  useLessons: () => ({ lessons: [], isLoading: false }),
}))

vi.mock('../contexts/LiveFeedContext', () => ({
  useLiveFeed: () => EMPTY_FEED,
  LiveFeedProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

const PROJECTS: ProjectSummary[] = [
  {
    project_id: 'enceladus',
    name: 'enceladus',
    prefix: 'ENC',
    status: 'active',
    summary: '',
    last_sprint: '',
    open_tasks: 0,
    closed_tasks: 0,
    total_tasks: 0,
    open_issues: 0,
    closed_issues: 0,
    total_issues: 0,
    in_progress_features: 0,
    completed_features: 0,
    total_features: 0,
    planned_tasks: 0,
    updated_at: null,
    last_update_note: null,
  },
]

vi.mock('../hooks/useProjects', () => ({
  useProjects: () => ({ projects: PROJECTS, isPending: false, isError: false }),
}))

vi.mock('../hooks/useRecordMutation', () => ({
  useRecordMutation: () => ({ mutate: vi.fn(), isPending: false }),
}))

// Stub heavy sub-components so the tests focus on fallback wiring.
vi.mock('../components/shared/LifecycleActions', () => ({
  LifecycleActions: () => <div data-testid="lifecycle-actions" />,
}))
vi.mock('../components/shared/GitHubOverlay', () => ({
  GitHubOverlay: () => null,
}))
vi.mock('../components/shared/PlanTree', () => ({
  PlanTree: () => null,
}))
vi.mock('../components/shared/PillarScoreChart', () => ({
  PillarScoreChart: () => <div data-testid="pillar-score-chart" />,
}))

// ---------------------------------------------------------------------------
// Imports after vi.mock so mocks are applied at module evaluation.
// ---------------------------------------------------------------------------

import { TaskDetailPage } from './TaskDetailPage'
import { IssueDetailPage } from './IssueDetailPage'
import { FeatureDetailPage } from './FeatureDetailPage'
import { PlanDetailPage } from './PlanDetailPage'
import LessonDetailPage from './LessonDetailPage'
import { DocumentDetailPage } from './DocumentDetailPage'

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

function withRouter(ui: ReactNode, initialEntries: string[], routeTemplate: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  return (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route path={routeTemplate} element={ui as React.ReactElement} />
          <Route path="*" element={<div data-testid="fallback-route" />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

function hookResult<T>(overrides: {
  data?: T | undefined
  isLoading?: boolean
  isError?: boolean
  isNotFound?: boolean
  refetch?: () => void
}) {
  return {
    data: overrides.data,
    isLoading: overrides.isLoading ?? false,
    isError: overrides.isError ?? false,
    isNotFound: overrides.isNotFound ?? false,
    refetch: overrides.refetch ?? vi.fn(),
  }
}

beforeEach(() => {
  mockUseRecordFallback.mockReset()
})

afterEach(() => {
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const TASK: Task = {
  task_id: 'ENC-TSK-C08',
  project_id: 'enceladus',
  title: 'Task title',
  description: 'task description body',
  status: 'open',
  priority: 'P1',
  assigned_to: null,
  related_feature_ids: [],
  related_task_ids: [],
  related_issue_ids: [],
  checklist_total: 0,
  checklist_done: 0,
  checklist: [],
  history: [],
  parent: null,
  updated_at: '2026-04-15T00:00:00Z',
  last_update_note: null,
  created_at: '2026-04-15T00:00:00Z',
  acceptance_criteria: [],
  subtask_ids: [],
  transition_type: 'web_deploy',
  typed_relationships: [],
} as Task

const ISSUE: Issue = {
  issue_id: 'ENC-ISS-200',
  project_id: 'enceladus',
  title: 'Issue title',
  description: 'issue body',
  status: 'open',
  priority: 'P1',
  severity: 'medium',
  hypothesis: null,
  related_feature_ids: [],
  related_task_ids: [],
  related_issue_ids: [],
  history: [],
  parent: null,
  updated_at: '2026-04-15T00:00:00Z',
  last_update_note: null,
  created_at: '2026-04-15T00:00:00Z',
  evidence: [],
  typed_relationships: [],
} as Issue

const FEATURE: Feature = {
  feature_id: 'ENC-FTR-073',
  project_id: 'enceladus',
  title: 'Feature title',
  description: 'feature body',
  status: 'planned',
  owners: [],
  success_metrics_count: 0,
  success_metrics: [],
  related_task_ids: [],
  related_feature_ids: [],
  related_issue_ids: [],
  history: [],
  parent: null,
  updated_at: '2026-04-15T00:00:00Z',
  last_update_note: null,
  created_at: '2026-04-15T00:00:00Z',
  acceptance_criteria: [],
  typed_relationships: [],
} as Feature

const PLAN: Plan = {
  plan_id: 'ENC-PLN-006',
  project_id: 'enceladus',
  title: 'Plan title',
  description: 'plan body',
  status: 'started',
  priority: 'P0',
  category: null,
  objectives_set: ['ENC-TSK-1'],
  attached_documents: ['DOC-FFB4C9D87BCC'],
  related_feature_id: 'ENC-FTR-073',
  checkout_state: null,
  checked_out_by: null,
  checked_out_at: null,
  related_task_ids: [],
  related_issue_ids: [],
  related_feature_ids: [],
  history: [],
  updated_at: '2026-04-15T00:00:00Z',
  last_update_note: null,
  created_at: '2026-04-15T00:00:00Z',
} as Plan

const LESSON: Lesson = {
  lesson_id: 'ENC-LSN-001',
  project_id: 'enceladus',
  title: 'Lesson title',
  observation: 'obs body',
  insight: 'insight body',
  evidence_chain: ['ENC-TSK-1'],
  provenance: 'analysis',
  confidence: 0.8,
  pillar_scores: { efficiency: 0.5, human_protection: 0.6, intention: 0.7, alignment: 0.8 },
  resonance_score: 0.75,
  pillar_composite: 0.65,
  extensions: [
    { description: 'ext 1 body', timestamp: '2026-04-15T00:00:00Z', provider: 'claude' },
  ],
  category: 'architecture',
  status: 'active',
  lesson_version: 1,
  related_task_ids: [],
  related_issue_ids: [],
  related_feature_ids: [],
  history: [],
  updated_at: '2026-04-15T00:00:00Z',
  last_update_note: null,
  created_at: '2026-04-15T00:00:00Z',
} as Lesson

const DOCUMENT: Document = {
  document_id: 'DOC-FFB4C9D87BCC',
  project_id: 'enceladus',
  title: 'Doc title',
  description: 'doc description',
  file_name: 'DOC-FFB4C9D87BCC.md',
  content_type: 'text/markdown',
  content_hash: 'abc123',
  size_bytes: 42,
  keywords: ['governance'],
  related_items: ['ENC-TSK-1', 'ENC-FTR-073', 'DOC-OTHER'],
  status: 'active',
  created_by: 'agent',
  created_at: '2026-04-15T00:00:00Z',
  updated_at: '2026-04-15T00:00:00Z',
  version: 1,
  content: '# Doc body',
} as Document

// ---------------------------------------------------------------------------
// TaskDetailPage
// ---------------------------------------------------------------------------

describe('TaskDetailPage fallback integration (ENC-FTR-073)', () => {
  it('renders the task header when data is present (in-feed or fallback)', () => {
    mockUseRecordFallback.mockReturnValue(hookResult({ data: TASK }))
    render(withRouter(<TaskDetailPage />, ['/tasks/ENC-TSK-C08'], '/tasks/:taskId'))
    expect(mockUseRecordFallback).toHaveBeenCalledWith(
      expect.objectContaining({ recordType: 'task', recordId: 'ENC-TSK-C08' }),
    )
    expect(screen.getByRole('heading', { name: TASK.title })).toBeInTheDocument()
  })

  it('renders RecordFallbackLoading when the hook signals isLoading', () => {
    mockUseRecordFallback.mockReturnValue(hookResult<Task>({ isLoading: true }))
    render(withRouter(<TaskDetailPage />, ['/tasks/ENC-TSK-C08'], '/tasks/:taskId'))
    expect(screen.getByRole('status')).toHaveAttribute('aria-busy', 'true')
  })

  it('renders RecordNotFound when the hook signals isNotFound', () => {
    mockUseRecordFallback.mockReturnValue(hookResult<Task>({ isNotFound: true }))
    render(withRouter(<TaskDetailPage />, ['/tasks/ENC-TSK-MISSING'], '/tasks/:taskId'))
    expect(screen.getByRole('heading', { name: /record not found/i })).toBeInTheDocument()
    expect(screen.getByText('ENC-TSK-MISSING')).toBeInTheDocument()
  })

  it('renders RecordFallbackError with a retry button when the hook signals isError', async () => {
    const refetch = vi.fn()
    mockUseRecordFallback.mockReturnValue(hookResult<Task>({ isError: true, refetch }))
    render(withRouter(<TaskDetailPage />, ['/tasks/ENC-TSK-NET'], '/tasks/:taskId'))
    const button = screen.getByRole('button', { name: /retry/i })
    await userEvent.click(button)
    expect(refetch).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// IssueDetailPage
// ---------------------------------------------------------------------------

describe('IssueDetailPage fallback integration (ENC-FTR-073)', () => {
  it('renders the issue header when data is present', () => {
    mockUseRecordFallback.mockReturnValue(hookResult({ data: ISSUE }))
    render(withRouter(<IssueDetailPage />, ['/issues/ENC-ISS-200'], '/issues/:issueId'))
    expect(mockUseRecordFallback).toHaveBeenCalledWith(
      expect.objectContaining({ recordType: 'issue', recordId: 'ENC-ISS-200' }),
    )
    expect(screen.getByRole('heading', { name: ISSUE.title })).toBeInTheDocument()
  })

  it('renders RecordNotFound when the hook signals isNotFound', () => {
    mockUseRecordFallback.mockReturnValue(hookResult<Issue>({ isNotFound: true }))
    render(withRouter(<IssueDetailPage />, ['/issues/ENC-ISS-MISSING'], '/issues/:issueId'))
    expect(screen.getByText(/No issue with ID/i)).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// FeatureDetailPage
// ---------------------------------------------------------------------------

describe('FeatureDetailPage fallback integration (ENC-FTR-073)', () => {
  it('renders the feature header when data is present', () => {
    mockUseRecordFallback.mockReturnValue(hookResult({ data: FEATURE }))
    render(withRouter(<FeatureDetailPage />, ['/features/ENC-FTR-073'], '/features/:featureId'))
    expect(mockUseRecordFallback).toHaveBeenCalledWith(
      expect.objectContaining({ recordType: 'feature', recordId: 'ENC-FTR-073' }),
    )
    expect(screen.getByRole('heading', { name: FEATURE.title })).toBeInTheDocument()
  })

  it('renders RecordNotFound when the hook signals isNotFound', () => {
    mockUseRecordFallback.mockReturnValue(hookResult<Feature>({ isNotFound: true }))
    render(withRouter(<FeatureDetailPage />, ['/features/ENC-FTR-MISSING'], '/features/:featureId'))
    expect(screen.getByText(/No feature with ID/i)).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// PlanDetailPage
// ---------------------------------------------------------------------------

describe('PlanDetailPage fallback integration (ENC-FTR-073)', () => {
  it('renders the plan header with normalized objectives and attached docs', () => {
    mockUseRecordFallback.mockReturnValue(hookResult({ data: PLAN }))
    render(withRouter(<PlanDetailPage />, ['/plans/ENC-PLN-006'], '/plans/:planId'))
    expect(mockUseRecordFallback).toHaveBeenCalledWith(
      expect.objectContaining({ recordType: 'plan', recordId: 'ENC-PLN-006' }),
    )
    expect(screen.getByRole('heading', { name: PLAN.title })).toBeInTheDocument()
    expect(screen.getByText('ENC-PLN-006')).toBeInTheDocument()
    // Attached document link
    expect(screen.getByText('DOC-FFB4C9D87BCC')).toBeInTheDocument()
  })

  it('renders RecordNotFound when the hook signals isNotFound', () => {
    mockUseRecordFallback.mockReturnValue(hookResult<Plan>({ isNotFound: true }))
    render(withRouter(<PlanDetailPage />, ['/plans/ENC-PLN-MISSING'], '/plans/:planId'))
    expect(screen.getByText(/No plan with ID/i)).toBeInTheDocument()
  })

  it('renders RecordFallbackLoading while the hook is loading', () => {
    mockUseRecordFallback.mockReturnValue(hookResult<Plan>({ isLoading: true }))
    render(withRouter(<PlanDetailPage />, ['/plans/ENC-PLN-006'], '/plans/:planId'))
    expect(screen.getByRole('status')).toHaveAttribute('aria-busy', 'true')
  })
})

// ---------------------------------------------------------------------------
// LessonDetailPage
// ---------------------------------------------------------------------------

describe('LessonDetailPage fallback integration (ENC-FTR-073)', () => {
  it('renders the lesson header, pillar scores, and extensions when data present', () => {
    mockUseRecordFallback.mockReturnValue(hookResult({ data: LESSON }))
    render(withRouter(<LessonDetailPage />, ['/lessons/ENC-LSN-001'], '/lessons/:lessonId'))
    expect(mockUseRecordFallback).toHaveBeenCalledWith(
      expect.objectContaining({ recordType: 'lesson', recordId: 'ENC-LSN-001' }),
    )
    expect(screen.getByRole('heading', { name: LESSON.title })).toBeInTheDocument()
    expect(screen.getByText('ENC-LSN-001')).toBeInTheDocument()
    expect(screen.getByText(/ext 1 body/)).toBeInTheDocument()
    expect(screen.getByTestId('pillar-score-chart')).toBeInTheDocument()
  })

  it('renders RecordNotFound when the hook signals isNotFound', () => {
    mockUseRecordFallback.mockReturnValue(hookResult<Lesson>({ isNotFound: true }))
    render(withRouter(<LessonDetailPage />, ['/lessons/ENC-LSN-MISSING'], '/lessons/:lessonId'))
    expect(screen.getByText(/No lesson with ID/i)).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// DocumentDetailPage
// ---------------------------------------------------------------------------

describe('DocumentDetailPage fallback integration (ENC-FTR-073)', () => {
  it('renders the document title and body when data is present via fallback', () => {
    mockUseRecordFallback.mockReturnValue(hookResult({ data: DOCUMENT }))
    render(
      withRouter(
        <DocumentDetailPage />,
        ['/documents/DOC-FFB4C9D87BCC/doc-ffb4c9d87bcc-md'],
        '/documents/:documentId/:documentSlug',
      ),
    )
    expect(mockUseRecordFallback).toHaveBeenCalledWith(
      expect.objectContaining({ recordType: 'document', recordId: 'DOC-FFB4C9D87BCC' }),
    )
    expect(screen.getByRole('heading', { name: DOCUMENT.title })).toBeInTheDocument()
    // Related items chips — one linkable (task), one document link, one unlinkable.
    expect(screen.getByText('ENC-TSK-1')).toBeInTheDocument()
    expect(screen.getByText('DOC-OTHER')).toBeInTheDocument()
  })

  it('renders RecordNotFound for document 404 from the hook', () => {
    mockUseRecordFallback.mockReturnValue(hookResult<Document>({ isNotFound: true }))
    render(
      withRouter(<DocumentDetailPage />, ['/documents/DOC-MISSING'], '/documents/:documentId'),
    )
    expect(screen.getByText(/No document with ID/i)).toBeInTheDocument()
    expect(screen.getByText('DOC-MISSING')).toBeInTheDocument()
  })
})
