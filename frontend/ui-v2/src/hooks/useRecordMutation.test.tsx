import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import {
  registerMutationErrorHandler,
  useRecordMutation,
  type MutationErrorState,
} from './useRecordMutation'
import { recordKeys } from '../api/queryOptions'
import { feedCorpusKeys } from '../api/feedCorpusQueryOptions'
import type { FeedCorpusPage } from '../sync/types'

/**
 * No @testing-library/react is installed in this package (every existing
 * ui-v2 test is logic-level, not component-level) — this is a minimal
 * createRoot + act harness using only what's already a dependency
 * (react-dom/client), matching src/primitives/SessionPrimitive.test.tsx.
 */

vi.mock('../api/mutations', async () => {
  const actual = await vi.importActual<typeof import('../api/mutations')>('../api/mutations')
  return {
    ...actual,
    closeRecord: vi.fn(),
    setField: vi.fn(),
    submitNote: vi.fn(),
  }
})

import { closeRecord, setField } from '../api/mutations'

const PROJECT_ID = 'enceladus'
const TASK_ID = 'ENC-TSK-K23'

function makeTask(status: string) {
  return { record_id: TASK_ID, status, title: 'Optimistic mutation layer', sync_version: 1 }
}

function makeFeedPage(status: string): FeedCorpusPage {
  return {
    success: true,
    items: [
      {
        record_id: TASK_ID,
        record_type: 'task',
        project_id: PROJECT_ID,
        title: 'Optimistic mutation layer',
        source: 'tracker',
        record_key: `task#${TASK_ID}`,
        attrs: { status },
      },
    ],
    next_cursor: null,
    facets: {},
    total_matches: 1,
  }
}

describe('useRecordMutation — five-step onMutate (B67 AC-5)', () => {
  let qc: QueryClient
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    vi.clearAllMocks()
    registerMutationErrorHandler(() => {})
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
    qc.clear()
  })

  function TriggerComponent({ onReady }: { onReady: (mutate: ReturnType<typeof useRecordMutation>['mutate']) => void }) {
    const mutation = useRecordMutation()
    onReady(mutation.mutate)
    return null
  }

  it('applies the optimistic write to cache before the network call resolves (zero perceptible loading state)', async () => {
    qc.setQueryData(recordKeys.detail('task', PROJECT_ID, TASK_ID), makeTask('in-progress'))

    let resolveFetch: (v: { success: true; record_id: string; updated_at: string }) => void = () => {}
    vi.mocked(setField).mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveFetch = resolve
        }),
    )

    let mutate!: ReturnType<typeof useRecordMutation>['mutate']
    act(() => {
      root.render(
        <QueryClientProvider client={qc}>
          <TriggerComponent onReady={(m) => (mutate = m)} />
        </QueryClientProvider>,
      )
    })

    await act(async () => {
      mutate({
        projectId: PROJECT_ID,
        recordType: 'task',
        recordId: TASK_ID,
        action: 'set_field',
        field: 'status',
        value: 'closed',
      })
      // onMutate's own steps (cancelQueries) are async, so the optimistic
      // write lands a microtask after mutate() returns — flush that, but
      // the mutationFn's fetch promise (resolveFetch) is still pending, so
      // this is still strictly "before the network call resolves."
      await Promise.resolve()
      await Promise.resolve()
    })

    // Cache already reflects the new value before the network round trip
    // completes — this is what "zero perceptible loading state" means.
    const optimistic = qc.getQueryData<{ status: string }>(recordKeys.detail('task', PROJECT_ID, TASK_ID))
    expect(optimistic?.status).toBe('closed')

    await act(async () => {
      resolveFetch({ success: true, record_id: TASK_ID, updated_at: '2026-07-07T15:30:00Z' })
      await Promise.resolve()
      await Promise.resolve()
    })

    // Step 5 (onSettled) invalidated the query — it's no longer fresh.
    expect(qc.getQueryState(recordKeys.detail('task', PROJECT_ID, TASK_ID))?.isInvalidated).toBe(true)
  })

  it('cancels outgoing refetches before snapshotting (step 1 precedes step 2)', async () => {
    qc.setQueryData(recordKeys.detail('task', PROJECT_ID, TASK_ID), makeTask('open'))
    const cancelSpy = vi.spyOn(qc, 'cancelQueries')
    vi.mocked(setField).mockResolvedValue({ success: true, record_id: TASK_ID, updated_at: 'x' })

    let mutate!: ReturnType<typeof useRecordMutation>['mutate']
    act(() => {
      root.render(
        <QueryClientProvider client={qc}>
          <TriggerComponent onReady={(m) => (mutate = m)} />
        </QueryClientProvider>,
      )
    })

    await act(async () => {
      mutate({
        projectId: PROJECT_ID,
        recordType: 'task',
        recordId: TASK_ID,
        action: 'set_field',
        field: 'status',
        value: 'in-progress',
      })
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(cancelSpy).toHaveBeenCalledWith({ queryKey: recordKeys.detail('task', PROJECT_ID, TASK_ID) })
  })
})

describe('useRecordMutation — cross-page propagation (B67 AC-6)', () => {
  let qc: QueryClient
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    vi.clearAllMocks()
    registerMutationErrorHandler(() => {})
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
    qc.clear()
  })

  it('one setQueryData call updates every consumer of the same key in the same pass — no cascading extra renders', async () => {
    qc.setQueryData(recordKeys.detail('task', PROJECT_ID, TASK_ID), makeTask('in-progress'))
    qc.setQueryData(feedCorpusKeys.page({}), makeFeedPage('in-progress'))
    vi.mocked(closeRecord).mockResolvedValue({ success: true, record_id: TASK_ID, updated_at: 'x' })

    const detailRenders = { taskDetailView: 0, parentPlanView: 0 }

    // Two independent consumers of the SAME query key — standing in for the
    // task detail page and the parent plan page, which both read
    // recordKeys.detail('task', ...) for this child task rather than the
    // plan embedding its own copy.
    function TaskDetailView() {
      const { data } = useQuery<{ status: string }>({
        queryKey: recordKeys.detail('task', PROJECT_ID, TASK_ID),
        queryFn: () => Promise.reject(new Error('should not refetch in this test')),
        enabled: false,
      })
      detailRenders.taskDetailView += 1
      return <span data-testid="task-detail">{data?.status}</span>
    }

    function ParentPlanView() {
      const { data } = useQuery<{ status: string }>({
        queryKey: recordKeys.detail('task', PROJECT_ID, TASK_ID),
        queryFn: () => Promise.reject(new Error('should not refetch in this test')),
        enabled: false,
      })
      detailRenders.parentPlanView += 1
      return <span data-testid="parent-plan">{data?.status}</span>
    }

    function FeedView() {
      const { data } = useQuery<FeedCorpusPage>({
        queryKey: feedCorpusKeys.page({}),
        queryFn: () => Promise.reject(new Error('should not refetch in this test')),
        enabled: false,
      })
      return <span data-testid="feed">{data?.items[0]?.attrs?.status as string}</span>
    }

    let mutate!: ReturnType<typeof useRecordMutation>['mutate']
    function TriggerComponent() {
      const mutation = useRecordMutation()
      mutate = mutation.mutate
      return null
    }

    act(() => {
      root.render(
        <QueryClientProvider client={qc}>
          <TaskDetailView />
          <ParentPlanView />
          <FeedView />
          <TriggerComponent />
        </QueryClientProvider>,
      )
    })

    expect(container.querySelector('[data-testid="task-detail"]')?.textContent).toBe('in-progress')
    expect(container.querySelector('[data-testid="parent-plan"]')?.textContent).toBe('in-progress')
    expect(container.querySelector('[data-testid="feed"]')?.textContent).toBe('in-progress')

    const rendersBeforeMutate = { ...detailRenders }

    await act(async () => {
      mutate({ projectId: PROJECT_ID, recordType: 'task', recordId: TASK_ID, action: 'close' })
      // Flush both the async onMutate steps AND notifyManager's own batched
      // observer notifications (queued via a macrotask, not a microtask).
      await new Promise((resolve) => setTimeout(resolve, 0))
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    // Both consumers of the shared key reflect the transition in the same
    // pass, and the independently-keyed feed cache also updated — three
    // tabs, one optimistic write, verified via the DOM.
    expect(container.querySelector('[data-testid="task-detail"]')?.textContent).toBe('closed')
    expect(container.querySelector('[data-testid="parent-plan"]')?.textContent).toBe('closed')
    expect(container.querySelector('[data-testid="feed"]')?.textContent).toBe('closed')

    // No cascade: each consumer re-rendered exactly once for the one
    // optimistic write, not once per other consumer's update.
    expect(detailRenders.taskDetailView).toBe(rendersBeforeMutate.taskDetailView + 1)
    expect(detailRenders.parentPlanView).toBe(rendersBeforeMutate.parentPlanView + 1)
  })
})

describe('useRecordMutation — atomic rollback + retry (B67 AC-7)', () => {
  let qc: QueryClient
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    vi.clearAllMocks()
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
    qc.clear()
  })

  function TriggerComponent({ onReady }: { onReady: (mutate: ReturnType<typeof useRecordMutation>['mutate']) => void }) {
    const mutation = useRecordMutation()
    onReady(mutation.mutate)
    return null
  }

  it('restores the exact pre-mutation snapshot on failure and surfaces a Flashbar Retry that resubmits', async () => {
    const originalTask = makeTask('in-progress')
    const originalFeed = makeFeedPage('in-progress')
    qc.setQueryData(recordKeys.detail('task', PROJECT_ID, TASK_ID), originalTask)
    qc.setQueryData(feedCorpusKeys.page({}), originalFeed)

    vi.mocked(setField).mockRejectedValueOnce(new Error('network error'))

    let capturedState: MutationErrorState | null = null
    registerMutationErrorHandler((state) => {
      capturedState = state
    })

    let mutate!: ReturnType<typeof useRecordMutation>['mutate']
    act(() => {
      root.render(
        <QueryClientProvider client={qc}>
          <TriggerComponent onReady={(m) => (mutate = m)} />
        </QueryClientProvider>,
      )
    })

    const vars = {
      projectId: PROJECT_ID,
      recordType: 'task' as const,
      recordId: TASK_ID,
      action: 'set_field' as const,
      field: 'status',
      value: 'closed',
    }

    await act(async () => {
      mutate(vars)
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
    })

    // Atomic rollback: BOTH caches touched by the optimistic write are back
    // to their exact pre-mutation snapshot — not a partial revert.
    expect(qc.getQueryData(recordKeys.detail('task', PROJECT_ID, TASK_ID))).toEqual(originalTask)
    expect(qc.getQueryData(feedCorpusKeys.page({}))).toEqual(originalFeed)

    // The Flashbar surface was notified with a Retry callback, not a raw
    // exception — this is the UI contract OfflineLayer's MutationErrorFlashbar
    // renders against.
    expect(capturedState).not.toBeNull()
    expect(capturedState!.open).toBe(true)
    expect(capturedState!.message).toBeTruthy()
    expect(typeof capturedState!.retry).toBe('function')

    // Clicking Retry resubmits the exact same vars.
    vi.mocked(setField).mockResolvedValueOnce({ success: true, record_id: TASK_ID, updated_at: 'x' })
    await act(async () => {
      capturedState!.retry!()
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(vi.mocked(setField)).toHaveBeenCalledTimes(2)
    expect(qc.getQueryData<{ status: string }>(recordKeys.detail('task', PROJECT_ID, TASK_ID))?.status).toBe('closed')
  })
})
