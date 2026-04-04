import { act, renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LiveFeedProvider, useLiveFeed } from './LiveFeedContext'

const { mockFetchLiveFeed, mockFetchLiveFeedDelta } = vi.hoisted(() => ({
  mockFetchLiveFeed: vi.fn(),
  mockFetchLiveFeedDelta: vi.fn(),
}))

vi.mock('../api/feeds', () => ({
  fetchLiveFeed: mockFetchLiveFeed,
  fetchLiveFeedDelta: mockFetchLiveFeedDelta,
}))

vi.mock('../lib/authSession', () => ({
  isSessionExpiredError: () => false,
}))

function wrapper({ children }: { children: ReactNode }) {
  return <LiveFeedProvider>{children}</LiveFeedProvider>
}

function task(id: string) {
  return {
    task_id: id,
    project_id: 'enceladus',
    title: `Task ${id}`,
    description: '',
    status: 'open' as const,
    priority: 'P1' as const,
    assigned_to: null,
    related_feature_ids: [],
    related_task_ids: [],
    related_issue_ids: [],
    checklist_total: 0,
    checklist_done: 0,
    checklist: [],
    history: [],
    parent: null,
    updated_at: '2026-02-26T01:00:00Z',
    last_update_note: null,
    created_at: '2026-02-26T01:00:00Z',
  }
}

describe('LiveFeedContext', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    Object.defineProperty(document, 'visibilityState', {
      get: () => 'visible',
      configurable: true,
    })
    mockFetchLiveFeed.mockReset()
    mockFetchLiveFeedDelta.mockReset()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('preserves detail fields when delta contains sparse record update (ENC-ISS-148)', async () => {
    const baseTime = new Date()
    const baselineGeneratedAt = baseTime.toISOString()
    const deltaGeneratedAt = new Date(baseTime.getTime() + 3000).toISOString()

    const fullTask = {
      ...task('ENC-TSK-001'),
      intent: 'Prevent data loss on re-render',
      acceptance_criteria: [{ description: 'Fields preserved', evidence: '', evidence_acceptance: false }],
      history: [{ timestamp: '2026-02-26T01:00:00Z', status: 'created', description: 'Created' }],
    }

    mockFetchLiveFeed.mockResolvedValue({
      generated_at: baselineGeneratedAt,
      version: '1.0',
      tasks: [fullTask],
      issues: [],
      features: [],
    })

    // Delta returns a sparse update with empty sentinels (matches live feed API)
    mockFetchLiveFeedDelta.mockResolvedValue({
      generated_at: deltaGeneratedAt,
      version: '1.0',
      tasks: [{
        task_id: 'ENC-TSK-001',
        project_id: 'enceladus',
        title: 'Task ENC-TSK-001',
        description: '',
        status: 'in-progress',
        priority: 'P1',
        checklist: [],
        history: [],
        updated_at: deltaGeneratedAt,
      }],
      issues: [],
      features: [],
      closed_ids: [],
    })

    const { result } = renderHook(() => useLiveFeed(), { wrapper })

    await waitFor(() => expect(result.current.generatedAt).toBe(baselineGeneratedAt))
    expect(result.current.tasks[0].intent).toBe('Prevent data loss on re-render')
    expect(result.current.tasks[0].acceptance_criteria).toHaveLength(1)

    // Trigger delta poll
    await act(async () => {
      vi.advanceTimersByTime(3000)
    })

    await waitFor(() => expect(result.current.generatedAt).toBe(deltaGeneratedAt))

    // Status should be updated
    expect(result.current.tasks[0].status).toBe('in-progress')
    // Detail fields from original full record should be preserved
    expect(result.current.tasks[0].intent).toBe('Prevent data loss on re-render')
    expect(result.current.tasks[0].acceptance_criteria).toHaveLength(1)
    expect(result.current.tasks[0].history).toHaveLength(1)
  })

  it('does not update context state when delta payload has no record changes', async () => {
    const baseTime = new Date()
    const baselineGeneratedAt = baseTime.toISOString()
    const deltaGeneratedAt = new Date(baseTime.getTime() + 3000).toISOString()

    mockFetchLiveFeed.mockResolvedValue({
      generated_at: baselineGeneratedAt,
      version: '1.0',
      tasks: [task('ENC-TSK-001')],
      issues: [],
      features: [],
    })
    mockFetchLiveFeedDelta.mockResolvedValue({
      generated_at: deltaGeneratedAt,
      version: '1.0',
      tasks: [],
      issues: [],
      features: [],
      closed_ids: [],
    })

    const { result } = renderHook(() => useLiveFeed(), { wrapper })

    await waitFor(() => expect(result.current.generatedAt).toBe(baselineGeneratedAt))
    expect(result.current.tasks).toHaveLength(1)

    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
    })

    await waitFor(() => expect(mockFetchLiveFeedDelta).toHaveBeenCalledTimes(1))
    expect(result.current.generatedAt).toBe(baselineGeneratedAt)
    expect(result.current.tasks).toHaveLength(1)
  })
})
