/**
 * ProjectCard.test.tsx — ENC-FTR-131 / ENC-TSK-N89
 *
 * The load-bearing test here is the navigation one. ProjectCard's entire surface is a
 * react-router <Link>, so a nested Edit button that forgets preventDefault/stopPropagation
 * routes the user to the detail page instead of opening the dialog — a regression that is
 * invisible until someone actually taps the control.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ProjectCard } from './ProjectCard'
import type { ProjectSummary } from '../../types/feeds'

vi.mock('../../api/projects', async () => {
  const actual = await vi.importActual<typeof import('../../api/projects')>(
    '../../api/projects'
  )
  return {
    ...actual,
    getProject: vi.fn(),
    updateProject: vi.fn(),
  }
})

// The real useAuthState returns a context value whose setAuthExpired is useCallback-stable
// and takes no arguments. The mock must match: returning a fresh object (or a fresh vi.fn())
// on every render would make any effect keyed on its identity re-run per keystroke.
const { mockAuthState } = vi.hoisted(() => ({
  mockAuthState: { setAuthExpired: vi.fn() },
}))

vi.mock('../../lib/authState', () => ({
  useAuthState: () => mockAuthState,
}))

import { getProject, updateProject } from '../../api/projects'

const mockGet = vi.mocked(getProject)
const mockUpdate = vi.mocked(updateProject)

const project: ProjectSummary = {
  project_id: 'finance',
  name: 'finance',
  prefix: 'FIN',
  status: 'development',
  summary: 'Project to manage my finances.',
  last_sprint: '',
  open_tasks: 3,
  closed_tasks: 1,
  total_tasks: 4,
  open_issues: 0,
  closed_issues: 0,
  total_issues: 0,
  in_progress_features: 0,
  completed_features: 2,
  total_features: 2,
  planned_tasks: 0,
  updated_at: '2026-08-13T00:00:00Z',
  last_update_note: null,
}

const record = {
  success: true,
  project: {
    project_id: 'finance',
    prefix: 'FIN',
    summary: 'Project to manage my finances.',
    status: 'development',
    repo: '',
    created_at: '2026-04-02T00:36:20Z',
    updated_at: '2026-04-02T00:36:20Z',
  },
}

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/projects']}>
        <Routes>
          <Route path="/projects" element={<ProjectCard project={project} />} />
          <Route path="/projects/:id" element={<div>DETAIL PAGE</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ProjectCard edit control', () => {
  beforeEach(() => {
    mockGet.mockReset()
    mockUpdate.mockReset()
    mockGet.mockResolvedValue(record as never)
  })
  afterEach(() => vi.clearAllMocks())

  it('renders an edit control on the card', () => {
    renderCard()
    expect(screen.getByRole('button', { name: /edit project finance/i })).toBeInTheDocument()
  })

  it('opens the dialog without navigating to the detail route', async () => {
    const user = userEvent.setup()
    renderCard()

    await user.click(screen.getByRole('button', { name: /edit project finance/i }))

    expect(await screen.findByRole('dialog')).toBeInTheDocument()
    // The regression this guards: a nested button without preventDefault navigates away.
    expect(screen.queryByText('DETAIL PAGE')).not.toBeInTheDocument()
  })

  it('still navigates to the detail route when the card body is tapped', async () => {
    const user = userEvent.setup()
    renderCard()

    await user.click(screen.getByText('Project to manage my finances.'))

    expect(await screen.findByText('DETAIL PAGE')).toBeInTheDocument()
  })

  it('prefills from the fetched record, not the feed summary', async () => {
    const user = userEvent.setup()
    mockGet.mockResolvedValue({
      ...record,
      project: { ...record.project, repo: 'https://github.com/NX-2021-L/finance' },
    } as never)
    renderCard()

    await user.click(screen.getByRole('button', { name: /edit project finance/i }))

    // repo exists only on the fetched record — the feed's ProjectSummary has no such field,
    // so seeing it proves the prefill source is the GET, not the card's own props.
    await waitFor(() =>
      expect(screen.getByLabelText(/repository url/i)).toHaveValue(
        'https://github.com/NX-2021-L/finance'
      )
    )
    expect(mockGet).toHaveBeenCalledWith('finance')
  })

  it('sends only the changed field on save', async () => {
    const user = userEvent.setup()
    mockUpdate.mockResolvedValue(record as never)
    renderCard()

    await user.click(screen.getByRole('button', { name: /edit project finance/i }))
    const repoInput = await screen.findByLabelText(/repository url/i)
    await user.type(repoInput, 'https://github.com/NX-2021-L/finance')
    await user.click(screen.getByRole('button', { name: /save changes/i }))

    await waitFor(() =>
      expect(mockUpdate).toHaveBeenCalledWith('finance', {
        repo: 'https://github.com/NX-2021-L/finance',
      })
    )
  })

  it('blocks submission and shows an inline error for an invalid repo URL', async () => {
    const user = userEvent.setup()
    renderCard()

    await user.click(screen.getByRole('button', { name: /edit project finance/i }))
    const repoInput = await screen.findByLabelText(/repository url/i)
    await user.type(repoInput, 'not-a-url')
    await user.click(screen.getByRole('button', { name: /save changes/i }))

    expect(await screen.findByText(/must be a valid url/i)).toBeInTheDocument()
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  it('refuses an empty patch rather than firing a pointless request', async () => {
    const user = userEvent.setup()
    renderCard()

    await user.click(screen.getByRole('button', { name: /edit project finance/i }))
    await screen.findByLabelText(/repository url/i)
    await user.click(screen.getByRole('button', { name: /save changes/i }))

    expect(await screen.findByText(/no changes to save/i)).toBeInTheDocument()
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  it('keeps the dialog open with input intact when the server rejects the save', async () => {
    const user = userEvent.setup()
    const { ProjectServiceError } = await vi.importActual<
      typeof import('../../api/projects')
    >('../../api/projects')
    mockUpdate.mockRejectedValue(
      new ProjectServiceError(400, 'immutable field(s) not editable: prefix')
    )
    renderCard()

    await user.click(screen.getByRole('button', { name: /edit project finance/i }))
    const repoInput = await screen.findByLabelText(/repository url/i)
    await user.type(repoInput, 'https://github.com/NX-2021-L/finance')
    await user.click(screen.getByRole('button', { name: /save changes/i }))

    expect(await screen.findByText(/immutable field/i)).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByLabelText(/repository url/i)).toHaveValue(
      'https://github.com/NX-2021-L/finance'
    )
  })
})
