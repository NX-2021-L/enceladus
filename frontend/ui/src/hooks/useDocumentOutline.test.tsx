/**
 * useDocumentOutline tests (ENC-TSK-P80 AC-1/AC-4).
 *
 * Mocks the manifest fetcher and the AppSync record-channel subscription at
 * the module boundary so the hook's own orchestration — manifest-first
 * loading, section slicing from a caller-supplied body, live-event-driven
 * manifest refetch, and changed-section diffing — is exercised without a
 * real network or WebSocket.
 */
import { useState } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useDocumentOutline } from './useDocumentOutline'
import type { DocumentManifest } from '../api/documentManifest'

const { mockFetchManifest, mockSubscribe, subscribeCalls } = vi.hoisted(() => ({
  mockFetchManifest: vi.fn(),
  mockSubscribe: vi.fn(),
  subscribeCalls: [] as Array<{ onEvent: () => void; onStatusChange?: (s: string) => void }>,
}))

vi.mock('../api/documentManifest', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/documentManifest')>()
  return { ...actual, fetchDocumentManifest: mockFetchManifest }
})

vi.mock('../lib/appsyncRecordChannel', () => ({
  subscribeToRecordChannel: (opts: { onEvent: () => void; onStatusChange?: (s: string) => void }) => {
    mockSubscribe(opts)
    subscribeCalls.push(opts)
    return vi.fn()
  },
}))

const MANIFEST_V1: DocumentManifest = {
  document_id: 'DOC-HOOK1',
  project_id: 'enceladus',
  title: 'Hook Test Doc',
  version: 1,
  content_hash: 'hash-v1',
  size_bytes: 50,
  updated_at: '2026-09-01T00:00:00Z',
  outline: [
    { heading_path: ['Alpha'], level: 2, ordinal: 0, block_id: null, line_start: 2, line_end: 4, section_bytes: 10 },
  ],
}

const BODY_V1 = ['# Hook Test Doc', '', '## Alpha', '', 'Alpha v1 text.', ''].join('\n')
const BODY_V2 = ['# Hook Test Doc', '', '## Alpha', '', 'Alpha v2 text (edited elsewhere).', ''].join(
  '\n',
)

function Harness({ initialBody }: { initialBody: string }) {
  const [body, setBody] = useState(initialBody)
  const outline = useDocumentOutline('DOC-HOOK1', body, {
    onLiveMutation: () => setBody(BODY_V2),
  })
  return (
    <div>
      <div data-testid="section-count">{outline.sections.length}</div>
      <div data-testid="changed-count">{outline.changedKeys.size}</div>
      <div data-testid="live-status">{outline.liveStatus}</div>
      {outline.sections.map((s) => (
        <div key={s.key} data-testid={`section-${s.key}`}>
          {s.body}
        </div>
      ))}
    </div>
  )
}

function renderHarness(initialBody: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <Harness initialBody={initialBody} />
    </QueryClientProvider>,
  )
}

describe('useDocumentOutline', () => {
  beforeEach(() => {
    mockFetchManifest.mockReset()
    mockSubscribe.mockReset()
    subscribeCalls.length = 0
    mockFetchManifest.mockResolvedValue(MANIFEST_V1)
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  it('loads the manifest and slices sections from the supplied body', async () => {
    renderHarness(BODY_V1)
    await waitFor(() => expect(screen.getByTestId('section-count').textContent).toBe('1'))
    expect(screen.getByTestId('section-alpha-0').textContent).toBe('Alpha v1 text.')
  })

  it('subscribes to the record channel for the document', async () => {
    renderHarness(BODY_V1)
    await waitFor(() => expect(mockSubscribe).toHaveBeenCalledTimes(1))
  })

  it('marks a section changed when a live event drives a body update that changes its text', async () => {
    renderHarness(BODY_V1)
    await waitFor(() => expect(screen.getByTestId('section-count').textContent).toBe('1'))
    expect(screen.getByTestId('changed-count').textContent).toBe('0')

    // Simulate the AppSync channel firing: this drives the harness's
    // onLiveMutation, which swaps in BODY_V2 (a genuinely different Alpha
    // section) — the hook should diff the resulting slicing and mark it.
    const onEvent = subscribeCalls[0]?.onEvent
    expect(onEvent).toBeTruthy()
    await act(async () => {
      onEvent?.()
    })

    await waitFor(() =>
      expect(screen.getByTestId('section-alpha-0').textContent).toBe(
        'Alpha v2 text (edited elsewhere).',
      ),
    )
    await waitFor(() => expect(screen.getByTestId('changed-count').textContent).toBe('1'))
  })
})
