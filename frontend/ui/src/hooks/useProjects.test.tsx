import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { useProjects } from './useProjects'

const { mockFetchProjects } = vi.hoisted(() => ({
  mockFetchProjects: vi.fn(),
}))

vi.mock('../api/feeds', () => ({
  feedKeys: {
    projects: ['feed', 'projects'],
  },
  fetchProjects: mockFetchProjects,
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

describe('useProjects', () => {
  it('returns normalized projects and generated timestamp', async () => {
    mockFetchProjects.mockResolvedValue({
      generated_at: '2026-02-24T00:00:00Z',
      projects: [
        {
          project_id: 'enceladus',
          name: 'enceladus',
          prefix: 'ENC',
          status: 'active_production',
          summary: 'demo',
          last_sprint: '',
          open_tasks: 1,
          closed_tasks: 0,
          total_tasks: 1,
          open_issues: 0,
          closed_issues: 0,
          total_issues: 0,
          in_progress_features: 0,
          completed_features: 0,
          total_features: 0,
          planned_tasks: 1,
          updated_at: null,
          last_update_note: null,
        },
      ],
    })

    const { result } = renderHook(() => useProjects(), { wrapper: createWrapper() })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.projects).toHaveLength(1)
    expect(result.current.projects[0].project_id).toBe('enceladus')
    expect(result.current.generatedAt).toBe('2026-02-24T00:00:00Z')
  })
})
