/**
 * LessonCandidatesPage tests — ENC-TSK-J53 / ENC-FTR-096 Ph3.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { LessonCandidate } from '../api/lessonCandidates'

const { mockFetchPending, mockApprove, mockReject } = vi.hoisted(() => ({
  mockFetchPending: vi.fn(),
  mockApprove: vi.fn(),
  mockReject: vi.fn(),
}))

vi.mock('../api/lessonCandidates', async (importOriginal) => {
  const original = await importOriginal<typeof import('../api/lessonCandidates')>()
  return {
    ...original,
    fetchPendingLessonCandidates: mockFetchPending,
    approveLessonCandidate: mockApprove,
    rejectLessonCandidate: mockReject,
  }
})

import { LessonCandidatesPage } from './LessonCandidatesPage'

function candidate(overrides: Partial<LessonCandidate> = {}): LessonCandidate {
  return {
    document_id: 'DOC-CAND-001',
    project_id: 'enceladus',
    title: 'LESSON-CANDIDATE — recurring cluster',
    description: 'Auto-drafted lesson candidate pending io review.',
    file_name: 'doc.md',
    content_type: 'text/markdown',
    content_hash: 'abc',
    size_bytes: 100,
    keywords: ['lesson-candidate'],
    related_items: ['DOC-HANDOFF-001'],
    status: 'active',
    created_by: 'system',
    created_at: '2026-07-02T06:00:00Z',
    updated_at: '2026-07-02T06:00:00Z',
    version: 1,
    handoff_status: 'pending',
    cluster_member_ids: ['ENC-TSK-A01', 'ENC-TSK-B02'],
    ...overrides,
  } as LessonCandidate
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const wrapper = ({ children }: { children: ReactNode }) => (
    <MemoryRouter>
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    </MemoryRouter>
  )
  return render(<LessonCandidatesPage />, { wrapper })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockFetchPending.mockResolvedValue([candidate()])
  mockApprove.mockResolvedValue({
    success: true,
    document_id: 'DOC-CAND-001',
    lesson_id: 'ENC-LSN-999',
    handoff_status: 'completed',
  })
  mockReject.mockResolvedValue({
    success: true,
    document_id: 'DOC-CAND-001',
    handoff_status: 'stale',
  })
})

describe('LessonCandidatesPage', () => {
  it('renders pending candidates with control-cluster approve/reject', async () => {
    renderPage()
    const card = await screen.findByTestId('candidate-card-DOC-CAND-001')
    expect(within(card).getByText('DOC-CAND-001')).toBeInTheDocument()
    expect(within(card).getByTestId('control-cluster')).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: /approve/i })).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: /^reject$/i })).toBeInTheDocument()
  })

  it('calls approve API with edited fields', async () => {
    const user = userEvent.setup()
    renderPage()
    const card = await screen.findByTestId('candidate-card-DOC-CAND-001')
    await user.click(within(card).getByRole('button', { name: /approve/i }))
    expect(mockApprove).toHaveBeenCalledWith('DOC-CAND-001', {
      title: 'LESSON-CANDIDATE — recurring cluster',
      observation: 'Auto-drafted lesson candidate pending io review.',
      insight: expect.stringContaining('ENC-TSK-A01'),
      provenance: 'human',
    })
  })

  it('calls reject API after reason entry', async () => {
    const user = userEvent.setup()
    renderPage()
    const card = await screen.findByTestId('candidate-card-DOC-CAND-001')
    await user.click(within(card).getByRole('button', { name: /^reject$/i }))
    await user.type(
      within(card).getByRole('textbox', { name: /rejection reason/i }),
      'Not actionable pattern for gamma.',
    )
    await user.click(within(card).getByRole('button', { name: /confirm reject/i }))
    expect(mockReject).toHaveBeenCalledWith(
      'DOC-CAND-001',
      'Not actionable pattern for gamma.',
    )
  })

  it('shows empty state when no pending candidates', async () => {
    mockFetchPending.mockResolvedValue([])
    renderPage()
    expect(await screen.findByText(/no pending lesson candidates/i)).toBeInTheDocument()
  })
})
