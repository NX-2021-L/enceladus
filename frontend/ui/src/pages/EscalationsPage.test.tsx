/**
 * EscalationsPage tests — ENC-TSK-J70 / ENC-FTR-121 Ph3 (DOC-5B888FCA43B8 §5.7).
 *
 * Scope (AC-5, AC-7):
 *   - Feed renders pending escalations newest-first with target id, mutation
 *     type, requesting agent, justification, and the fresh diff.
 *   - The drift warning renders prominently when diff.drift.detected.
 *   - Approve / Deny / Deny-with-guidance wire to the API module.
 *   - Terminal escalations render inside the collapsed History section.
 *
 * Mocks: the api/escalations module is stubbed at the import boundary so the
 * page renders without the network; approval calls are asserted on the mock.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { EscalationItem, EscalationsFeedResponse } from '../api/escalations'

const { mockFetchEscalations, mockApprove, mockDeny } = vi.hoisted(() => ({
  mockFetchEscalations: vi.fn(),
  mockApprove: vi.fn(),
  mockDeny: vi.fn(),
}))

vi.mock('../api/escalations', async (importOriginal) => {
  const original = await importOriginal<typeof import('../api/escalations')>()
  return {
    ...original,
    fetchEscalations: mockFetchEscalations,
    approveEscalation: mockApprove,
    denyEscalation: mockDeny,
  }
})

import { EscalationsPage } from './EscalationsPage'

function pendingEscalation(overrides: Partial<EscalationItem> = {}): EscalationItem {
  return {
    item_id: 'ENC-ESC-001',
    project_id: 'enceladus',
    status: 'requested',
    mutation_type: 'deploy_arc_change',
    target_record_id: 'ENC-TSK-J10',
    justification: 'Arc misclassified at create; no deployable artifact.',
    payload: { new_deploy_arc_type: 'code_only' },
    requested_by: { session_id: 'ENC-SES-02F' },
    created_at: '2026-07-02T04:00:00Z',
    updated_at: '2026-07-02T04:00:00Z',
    diff: {
      mutation_type: 'deploy_arc_change',
      field: 'transition_type',
      current: 'github_pr_deploy',
      requested: 'code_only',
      target_snapshot: {
        title: 'Full CFN drift close-out',
        status: 'in-progress',
        transition_type: 'github_pr_deploy',
        sync_version: 4,
        updated_at: '2026-07-02T03:00:00Z',
      },
    },
    ...overrides,
  }
}

function feed(overrides: Partial<EscalationsFeedResponse> = {}): EscalationsFeedResponse {
  return {
    success: true,
    project_id: 'enceladus',
    pending: [pendingEscalation()],
    terminal: [
      pendingEscalation({
        item_id: 'ENC-ESC-000',
        status: 'denied_with_guidance',
        guidance_note: 'Use a successor task instead.',
        diff: undefined,
      }),
    ],
    count: 2,
    ...overrides,
  }
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
  return render(<EscalationsPage />, { wrapper })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockFetchEscalations.mockResolvedValue(feed())
  mockApprove.mockResolvedValue({
    success: true,
    escalation_id: 'ENC-ESC-001',
    status: 'applied',
    applied: true,
  })
  mockDeny.mockResolvedValue({
    success: true,
    escalation_id: 'ENC-ESC-001',
    status: 'denied',
  })
})

describe('EscalationsPage', () => {
  it('renders pending cards with target, mutation type, requester, justification, and diff', async () => {
    renderPage()
    const card = await screen.findByTestId('escalation-card-ENC-ESC-001')
    expect(within(card).getByText('ENC-TSK-J10')).toBeInTheDocument()
    expect(within(card).getByText('deploy_arc_change')).toBeInTheDocument()
    expect(within(card).getByText('ENC-SES-02F')).toBeInTheDocument()
    expect(
      within(card).getByText('Arc misclassified at create; no deployable artifact.'),
    ).toBeInTheDocument()
    const diff = within(card).getByTestId('escalation-diff')
    expect(within(diff).getByText('github_pr_deploy')).toBeInTheDocument()
    expect(within(diff).getByText('code_only')).toBeInTheDocument()
  })

  it('shows a prominent drift warning when expected_version mismatches', async () => {
    mockFetchEscalations.mockResolvedValue(
      feed({
        pending: [
          pendingEscalation({
            diff: {
              mutation_type: 'deploy_arc_change',
              field: 'transition_type',
              current: 'github_pr_deploy',
              requested: 'code_only',
              drift: {
                expected_version: 'sync_version:3',
                current_sync_version: '7',
                current_updated_at: '2026-07-02T04:10:00Z',
                detected: true,
              },
            },
          }),
        ],
      }),
    )
    renderPage()
    const warning = await screen.findByTestId('drift-warning')
    expect(warning.textContent).toContain('drifted')
    expect(warning.textContent).toContain('sync_version:3')
  })

  it('does not render a drift warning without drift', async () => {
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    expect(screen.queryByTestId('drift-warning')).toBeNull()
  })

  it('approve button calls approveEscalation with the escalation id', async () => {
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(mockApprove).toHaveBeenCalledWith('enceladus', 'ENC-ESC-001')
  })

  it('deny button calls denyEscalation without a guidance note', async () => {
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    await userEvent.click(screen.getByRole('button', { name: 'Deny' }))
    expect(mockDeny).toHaveBeenCalledWith('enceladus', 'ENC-ESC-001', undefined)
  })

  it('deny-with-guidance sends the note', async () => {
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    await userEvent.click(screen.getByRole('button', { name: 'Deny with guidance' }))
    await userEvent.type(
      screen.getByLabelText('Guidance note'),
      'Open a successor task instead.',
    )
    await userEvent.click(screen.getByRole('button', { name: 'Send denial' }))
    expect(mockDeny).toHaveBeenCalledWith(
      'enceladus',
      'ENC-ESC-001',
      'Open a successor task instead.',
    )
  })

  it('terminal escalations render in the collapsed History audit section', async () => {
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    const history = screen.getByTestId('terminal-section')
    expect(within(history).getByText('History (1)')).toBeInTheDocument()
    expect(within(history).getByText('ENC-ESC-000')).toBeInTheDocument()
    expect(within(history).getByText(/Use a successor task instead\./)).toBeInTheDocument()
  })

  it('renders the empty state when nothing is pending', async () => {
    mockFetchEscalations.mockResolvedValue(feed({ pending: [], terminal: [] }))
    renderPage()
    expect(await screen.findByText('No pending escalations.')).toBeInTheDocument()
  })
})
