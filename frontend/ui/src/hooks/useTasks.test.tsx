import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { TaskFilters } from '../types/filters'
import { useTasks } from './useTasks'

const { mockFetchTasks, mockUseLiveFeed } = vi.hoisted(() => ({
  mockFetchTasks: vi.fn(),
  mockUseLiveFeed: vi.fn(),
}))

vi.mock('../api/feeds', () => ({
  feedKeys: {
    tasks: ['feed', 'tasks'],
  },
  fetchTasks: mockFetchTasks,
}))

vi.mock('../contexts/LiveFeedContext', () => ({
  useLiveFeed: mockUseLiveFeed,
}))

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('useTasks', () => {
  beforeEach(() => {
    mockFetchTasks.mockReset()
    mockUseLiveFeed.mockReset()
    mockUseLiveFeed.mockReturnValue({
      tasks: [],
      issues: [],
      features: [],
      generatedAt: null,
      isPending: true,
      isError: false,
    })
  })

  it('filters by project/status/priority/search and sorts by priority asc', async () => {
    mockFetchTasks.mockResolvedValue({
      generated_at: '2026-02-24T00:00:00Z',
      tasks: [
        {
          task_id: 'ENC-TSK-001',
          project_id: 'enceladus',
          title: 'Investigate MCP startup',
          description: '',
          status: 'open',
          priority: 'P0',
          assigned_to: null,
          related_feature_ids: [],
          related_task_ids: [],
          related_issue_ids: [],
          checklist_total: 0,
          checklist_done: 0,
          checklist: [],
          history: [],
          parent: null,
          updated_at: '2026-02-24T02:00:00Z',
          last_update_note: null,
          created_at: '2026-02-24T01:00:00Z',
        },
        {
          task_id: 'ENC-TSK-002',
          project_id: 'enceladus',
          title: 'Add docs for bootstrap',
          description: '',
          status: 'open',
          priority: 'P2',
          assigned_to: null,
          related_feature_ids: [],
          related_task_ids: [],
          related_issue_ids: [],
          checklist_total: 0,
          checklist_done: 0,
          checklist: [],
          history: [],
          parent: null,
          updated_at: '2026-02-24T03:00:00Z',
          last_update_note: null,
          created_at: '2026-02-24T01:30:00Z',
        },
        {
          task_id: 'ENC-TSK-003',
          project_id: 'other',
          title: 'Other project task',
          description: '',
          status: 'closed',
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
          updated_at: '2026-02-24T04:00:00Z',
          last_update_note: null,
          created_at: '2026-02-24T00:30:00Z',
        },
      ],
    })

    const filters: TaskFilters = {
      projectId: 'enceladus',
      status: ['open'],
      priority: ['P0', 'P2'],
      search: 'enc-tsk',
      sortBy: 'priority:asc',
    }

    const { result } = renderHook(() => useTasks(filters), { wrapper: createWrapper() })

    await waitFor(() => expect(result.current.tasks).toHaveLength(2))
    expect(result.current.tasks).toHaveLength(2)
    expect(result.current.tasks[0].task_id).toBe('ENC-TSK-002')
    expect(result.current.tasks[1].task_id).toBe('ENC-TSK-001')
    expect(result.current.allTasks).toHaveLength(3)
    expect(result.current.generatedAt).toBe('2026-02-24T00:00:00Z')
  })

  it('merges live sparse data with S3 rich data to preserve detail fields (ENC-ISS-148)', async () => {
    // S3 feed has full records with description, history, checklist, AC
    mockFetchTasks.mockResolvedValue({
      generated_at: '2026-02-24T00:00:00Z',
      tasks: [
        {
          task_id: 'ENC-TSK-001',
          project_id: 'enceladus',
          title: 'Full record from S3',
          description: 'Detailed description from S3 feed',
          status: 'open',
          priority: 'P1',
          assigned_to: null,
          related_feature_ids: [],
          related_task_ids: [],
          related_issue_ids: [],
          checklist_total: 2,
          checklist_done: 1,
          checklist: ['Step 1 done', 'Step 2 pending'],
          history: [{ timestamp: '2026-02-24T01:00:00Z', status: 'created', description: 'Created' }],
          parent: null,
          updated_at: '2026-02-24T02:00:00Z',
          last_update_note: null,
          created_at: '2026-02-24T01:00:00Z',
          intent: 'Test intent from S3',
          acceptance_criteria: [{ description: 'AC from S3', evidence: '', evidence_acceptance: false }],
        },
      ],
    })

    // Live feed has sparse records (description="", history=[], checklist=[])
    // but with updated status
    mockUseLiveFeed.mockReturnValue({
      tasks: [
        {
          task_id: 'ENC-TSK-001',
          project_id: 'enceladus',
          title: 'Full record from S3',
          description: '',
          status: 'in-progress',
          priority: 'P1',
          assigned_to: null,
          related_feature_ids: [],
          related_task_ids: [],
          related_issue_ids: [],
          checklist_total: 2,
          checklist_done: 1,
          checklist: [],
          history: [],
          parent: null,
          updated_at: '2026-02-25T01:00:00Z',
          last_update_note: 'Status updated',
          created_at: '2026-02-24T01:00:00Z',
          intent: 'Test intent from S3',
          acceptance_criteria: [{ description: 'AC from S3', evidence: '', evidence_acceptance: false }],
        },
      ],
      issues: [],
      features: [],
      generatedAt: '2026-02-25T00:00:00Z',
      isPending: false,
      isError: false,
    })

    const { result } = renderHook(() => useTasks(), { wrapper: createWrapper() })

    // Wait for S3 query to resolve and merge to produce rich merged records
    await waitFor(() => expect(result.current.allTasks[0]?.description).toBe('Detailed description from S3 feed'))

    // Status should come from live (updated)
    expect(result.current.allTasks[0].status).toBe('in-progress')
    expect(result.current.allTasks[0].last_update_note).toBe('Status updated')

    // Detail fields should be preserved from S3 (not overwritten by empty sentinels)
    expect(result.current.allTasks[0].description).toBe('Detailed description from S3 feed')
    expect(result.current.allTasks[0].history).toHaveLength(1)
    expect(result.current.allTasks[0].checklist).toHaveLength(2)
    expect(result.current.allTasks[0].intent).toBe('Test intent from S3')
    expect(result.current.allTasks[0].acceptance_criteria).toHaveLength(1)
  })

  it('prefers live snapshot even when live task list is empty', async () => {
    mockUseLiveFeed.mockReturnValue({
      tasks: [],
      issues: [],
      features: [],
      generatedAt: '2026-02-25T00:00:00Z',
      isPending: false,
      isError: false,
    })
    mockFetchTasks.mockResolvedValue({
      generated_at: '2026-02-24T00:00:00Z',
      tasks: [
        {
          task_id: 'ENC-TSK-999',
          project_id: 'enceladus',
          title: 'stale',
          description: '',
          status: 'open',
          priority: 'P2',
          assigned_to: null,
          related_feature_ids: [],
          related_task_ids: [],
          related_issue_ids: [],
          checklist_total: 0,
          checklist_done: 0,
          checklist: [],
          history: [],
          parent: null,
          updated_at: '2026-02-24T03:00:00Z',
          last_update_note: null,
          created_at: '2026-02-24T01:30:00Z',
        },
      ],
    })

    const { result } = renderHook(() => useTasks(), { wrapper: createWrapper() })

    await waitFor(() => expect(result.current.isPending).toBe(false))
    expect(result.current.tasks).toEqual([])
    expect(result.current.allTasks).toEqual([])
    expect(result.current.generatedAt).toBe('2026-02-25T00:00:00Z')
  })
})
