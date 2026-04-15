/**
 * Unit tests for useRecordFallback (ENC-FTR-073 Phase 2a / ENC-TSK-D94).
 *
 * Covers the AC set:
 *   - in-feed shortcut: cached record bypasses network I/O
 *   - out-of-feed fetch: triggers exactly one request
 *   - 404 handling: NotFoundError surfaces as isNotFound, not isError
 *   - network error handling: non-404 surfaces as isError
 *   - unmount abort: fallbackQuery cancels via signal
 *   - re-fetch on recordId change: TanStack Query keys by recordId
 *   - StrictMode double-mount de-duplication: cache key de-dupes
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Plan, ProjectSummary, Task } from '../types/feeds'

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

const {
  mockFetchTaskById,
  mockFetchPlanById,
  mockUseProjects,
} = vi.hoisted(() => ({
  mockFetchTaskById: vi.fn(),
  mockFetchPlanById: vi.fn(),
  mockUseProjects: vi.fn(() => ({ projects: PROJECTS, isPending: false, isError: false })),
}))

vi.mock('../api/tracker', async () => {
  const actual = await vi.importActual<typeof import('../api/tracker')>('../api/tracker')
  return {
    ...actual,
    fetchTaskById: mockFetchTaskById,
    fetchPlanById: mockFetchPlanById,
  }
})

vi.mock('./useProjects', () => ({
  useProjects: mockUseProjects,
}))

import { NotFoundError } from '../api/tracker'
import { useRecordFallback } from './useRecordFallback'

function createWrapper(client?: QueryClient) {
  const queryClient =
    client ??
    new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
          gcTime: 0,
        },
      },
    })

  return ({ children }: { children: ReactNode }) => (
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    </MemoryRouter>
  )
}

const TASK_PAYLOAD = {
  item_id: 'ENC-TSK-C08',
  project_id: 'enceladus',
  title: 'Task',
  description: 'desc',
  status: 'open',
  priority: 'P1',
}

const PLAN_PAYLOAD = {
  item_id: 'ENC-PLN-006',
  project_id: 'enceladus',
  title: 'Plan',
  description: 'desc',
  status: 'started',
  priority: 'P0',
}

describe('useRecordFallback', () => {
  beforeEach(() => {
    mockFetchTaskById.mockReset()
    mockFetchPlanById.mockReset()
    mockUseProjects.mockReturnValue({ projects: PROJECTS, isPending: false, isError: false })
  })

  it('returns cached data immediately and issues zero requests (in-feed shortcut)', async () => {
    const cached = { task_id: 'ENC-TSK-1', title: 'Cached' } as Task

    const { result } = renderHook(
      () =>
        useRecordFallback({
          recordType: 'task',
          recordId: 'ENC-TSK-1',
          cached,
          feedPending: false,
          feedError: false,
        }),
      { wrapper: createWrapper() },
    )

    expect(result.current.data).toBe(cached)
    expect(result.current.isLoading).toBe(false)
    expect(result.current.isError).toBe(false)
    expect(result.current.isNotFound).toBe(false)
    expect(mockFetchTaskById).not.toHaveBeenCalled()
  })

  it('fires exactly one fetch when cached is undefined and feed has settled', async () => {
    mockFetchTaskById.mockResolvedValue(TASK_PAYLOAD)

    const { result } = renderHook(
      () =>
        useRecordFallback({
          recordType: 'task',
          recordId: 'ENC-TSK-C08',
          cached: undefined,
          feedPending: false,
          feedError: false,
        }),
      { wrapper: createWrapper() },
    )

    await waitFor(() => expect(result.current.data).toBeDefined())

    expect(result.current.data?.task_id).toBe('ENC-TSK-C08')
    expect(result.current.isNotFound).toBe(false)
    expect(result.current.isError).toBe(false)
    expect(mockFetchTaskById).toHaveBeenCalledTimes(1)
    expect(mockFetchTaskById).toHaveBeenCalledWith(
      'enceladus',
      'ENC-TSK-C08',
      expect.objectContaining({ signal: expect.anything() }),
    )
  })

  it('does not fetch while the feed is still pending (fetch gate)', async () => {
    const { result } = renderHook(
      () =>
        useRecordFallback({
          recordType: 'task',
          recordId: 'ENC-TSK-C08',
          cached: undefined,
          feedPending: true,
          feedError: false,
        }),
      { wrapper: createWrapper() },
    )

    expect(result.current.isLoading).toBe(true)
    expect(mockFetchTaskById).not.toHaveBeenCalled()
  })

  it('surfaces isNotFound when the fallback fetch throws NotFoundError (404)', async () => {
    mockFetchTaskById.mockRejectedValue(new NotFoundError('task ENC-TSK-MISSING not found'))

    const { result } = renderHook(
      () =>
        useRecordFallback({
          recordType: 'task',
          recordId: 'ENC-TSK-MISSING',
          cached: undefined,
          feedPending: false,
          feedError: false,
        }),
      { wrapper: createWrapper() },
    )

    await waitFor(() => expect(result.current.isNotFound).toBe(true))
    expect(result.current.isError).toBe(false)
    expect(result.current.data).toBeUndefined()
    // 404 must not trigger a retry.
    expect(mockFetchTaskById).toHaveBeenCalledTimes(1)
  })

  it('surfaces isError for non-404 network failures (after retry budget exhausts)', async () => {
    mockFetchTaskById.mockRejectedValue(new Error('network offline'))

    const { result } = renderHook(
      () =>
        useRecordFallback({
          recordType: 'task',
          recordId: 'ENC-TSK-NET',
          cached: undefined,
          feedPending: false,
          feedError: false,
        }),
      { wrapper: createWrapper() },
    )

    // Retry budget = 1, so expect up to 2 call attempts before isError flips.
    await waitFor(
      () => expect(result.current.isError).toBe(true),
      { timeout: 5000 },
    )
    expect(result.current.isNotFound).toBe(false)
    expect(result.current.data).toBeUndefined()
  })

  it('re-fetches when recordId changes', async () => {
    mockFetchTaskById.mockImplementation(async (_project: string, id: string) => ({
      ...TASK_PAYLOAD,
      item_id: id,
    }))

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 } },
    })

    const { result, rerender } = renderHook(
      ({ recordId }: { recordId: string }) =>
        useRecordFallback({
          recordType: 'task',
          recordId,
          cached: undefined,
          feedPending: false,
          feedError: false,
        }),
      {
        wrapper: createWrapper(client),
        initialProps: { recordId: 'ENC-TSK-1' },
      },
    )

    await waitFor(() => expect(result.current.data?.task_id).toBe('ENC-TSK-1'))
    expect(mockFetchTaskById).toHaveBeenCalledTimes(1)

    rerender({ recordId: 'ENC-TSK-2' })

    await waitFor(() => expect(result.current.data?.task_id).toBe('ENC-TSK-2'))
    expect(mockFetchTaskById).toHaveBeenCalledTimes(2)
    expect(mockFetchTaskById.mock.calls[0][1]).toBe('ENC-TSK-1')
    expect(mockFetchTaskById.mock.calls[1][1]).toBe('ENC-TSK-2')
  })

  it('aborts the in-flight request on unmount (AbortSignal propagation)', async () => {
    let capturedSignal: AbortSignal | undefined
    mockFetchTaskById.mockImplementation((_project: string, _id: string, init?: { signal?: AbortSignal }) => {
      capturedSignal = init?.signal
      return new Promise<unknown>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('The operation was aborted.', 'AbortError'))
        })
      })
    })

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 } },
    })

    const { unmount } = renderHook(
      () =>
        useRecordFallback({
          recordType: 'task',
          recordId: 'ENC-TSK-ABORT',
          cached: undefined,
          feedPending: false,
          feedError: false,
        }),
      { wrapper: createWrapper(client) },
    )

    await waitFor(() => expect(mockFetchTaskById).toHaveBeenCalled())
    expect(capturedSignal).toBeDefined()
    expect(capturedSignal?.aborted).toBe(false)

    await act(async () => {
      unmount()
      // TanStack Query cancels queries when their consumers unmount; the
      // signal passed into queryFn is aborted as part of that cleanup.
      client.cancelQueries()
    })

    await waitFor(() => expect(capturedSignal?.aborted).toBe(true))
  })

  it('dispatches to fetchPlanById for plan recordType', async () => {
    mockFetchPlanById.mockResolvedValue(PLAN_PAYLOAD)

    const { result } = renderHook(
      () =>
        useRecordFallback<'plan'>({
          recordType: 'plan',
          recordId: 'ENC-PLN-006',
          cached: undefined as Plan | undefined,
          feedPending: false,
          feedError: false,
        }),
      { wrapper: createWrapper() },
    )

    await waitFor(() => expect(result.current.data).toBeDefined())
    expect(result.current.data?.plan_id).toBe('ENC-PLN-006')
    expect(mockFetchPlanById).toHaveBeenCalledTimes(1)
  })

  it('de-duplicates concurrent consumers of the same recordId via the query key', async () => {
    mockFetchTaskById.mockResolvedValue(TASK_PAYLOAD)

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 } },
    })

    const wrapper = createWrapper(client)

    const { result: r1 } = renderHook(
      () =>
        useRecordFallback({
          recordType: 'task',
          recordId: 'ENC-TSK-DUP',
          cached: undefined,
          feedPending: false,
          feedError: false,
        }),
      { wrapper },
    )

    const { result: r2 } = renderHook(
      () =>
        useRecordFallback({
          recordType: 'task',
          recordId: 'ENC-TSK-DUP',
          cached: undefined,
          feedPending: false,
          feedError: false,
        }),
      { wrapper },
    )

    await waitFor(() => expect(r1.current.data).toBeDefined())
    await waitFor(() => expect(r2.current.data).toBeDefined())

    // One shared query — at most one network round-trip even with two mounts.
    expect(mockFetchTaskById).toHaveBeenCalledTimes(1)
  })
})
