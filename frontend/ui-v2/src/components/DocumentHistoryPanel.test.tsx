import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { DocumentHistoryEvent } from '../api/documentHistory'

/**
 * ENC-TSK-P81 (AC-3). No @testing-library/react in this package — createRoot
 * + act, matching src/components/DocumentSection.test.tsx /
 * DocumentSectionsView.test.tsx. The api module is mocked directly (this
 * component does not use TanStack Query, so no QueryClientProvider harness
 * is needed — see api/documentHistory.ts / components/DocumentHistoryPanel.tsx).
 */

vi.mock('../api/documentHistory', async () => {
  const actual = await vi.importActual<typeof import('../api/documentHistory')>('../api/documentHistory')
  return {
    ...actual,
    fetchDocumentHistory: vi.fn(),
    fetchDocumentAtVersion: vi.fn(),
    fetchDocumentDiff: vi.fn(),
  }
})

import {
  fetchDocumentAtVersion,
  fetchDocumentDiff,
  fetchDocumentHistory,
  sha256Hex,
} from '../api/documentHistory'
import {
  DocumentDiffPane,
  DocumentHistoryEventRow,
  DocumentHistoryPanel,
  DocumentRewindPane,
} from './DocumentHistoryPanel'

const DOC_ID = 'DOC-TEST01'
const PROJECT_ID = 'enceladus'

function makeEvent(overrides: Partial<DocumentHistoryEvent> = {}): DocumentHistoryEvent {
  return {
    event_id: 'evt-1',
    ts: '2026-09-01T00:00:00Z',
    actor: 'alice',
    surface: 'pwa',
    op: 'replace',
    anchor: { heading_path: ['Intro'], ordinal: 0, block_id: 'blk-1' },
    before_hash: 'hash-0',
    after_hash: 'hash-1',
    before_version: 1,
    after_version: 2,
    patch_bytes: 12,
    document_bytes: 100,
    diff_available: true,
    ...overrides,
  }
}

describe('DocumentHistoryPanel', () => {
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    vi.clearAllMocks()
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  async function flush(times = 2) {
    for (let i = 0; i < times; i++) {
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 0))
      })
    }
  }

  async function renderPanel() {
    await act(async () => {
      root.render(<DocumentHistoryPanel documentId={DOC_ID} projectId={PROJECT_ID} />)
    })
    await flush()
  }

  function eventRows() {
    return Array.from(container.querySelectorAll<HTMLButtonElement>('[data-testid^="history-event-"]'))
  }

  it('lists events newest-first (server returns ts-ascending, UI reverses)', async () => {
    vi.mocked(fetchDocumentHistory).mockResolvedValue({
      events: [
        makeEvent({ event_id: 'evt-old', ts: '2026-09-01T00:00:00Z', actor: 'alice' }),
        makeEvent({ event_id: 'evt-new', ts: '2026-09-02T00:00:00Z', actor: 'bob' }),
      ],
      next_cursor: null,
    })

    await renderPanel()

    const rows = eventRows()
    expect(rows.map((r) => r.dataset.testid)).toEqual(['history-event-evt-new', 'history-event-evt-old'])
  })

  it('appends the next cursor page (also reversed) after "Load older"', async () => {
    vi.mocked(fetchDocumentHistory).mockResolvedValueOnce({
      events: [makeEvent({ event_id: 'evt-2', ts: '2026-09-02T00:00:00Z' })],
      next_cursor: 'cursor-1',
    })
    await renderPanel()
    expect(eventRows().map((r) => r.dataset.testid)).toEqual(['history-event-evt-2'])

    vi.mocked(fetchDocumentHistory).mockResolvedValueOnce({
      events: [makeEvent({ event_id: 'evt-1', ts: '2026-09-01T00:00:00Z' })],
      next_cursor: null,
    })
    const loadMore = Array.from(container.querySelectorAll('button')).find((b) => b.textContent === 'Load older')
    expect(loadMore).toBeTruthy()
    act(() => {
      loadMore?.click()
    })
    await flush()

    expect(eventRows().map((r) => r.dataset.testid)).toEqual(['history-event-evt-2', 'history-event-evt-1'])
    expect(fetchDocumentHistory).toHaveBeenCalledWith(
      DOC_ID,
      PROJECT_ID,
      expect.objectContaining({ cursor: 'cursor-1' }),
    )
  })

  it('visually distinguishes rejected events (rejection_code)', async () => {
    vi.mocked(fetchDocumentHistory).mockResolvedValue({
      events: [
        makeEvent({ event_id: 'evt-ok' }),
        makeEvent({ event_id: 'evt-bad', op: 'replace-rejected', rejection_code: 'ANCHOR_NOT_FOUND' }),
      ],
      next_cursor: null,
    })

    await renderPanel()

    const rejectedRow = container.querySelector('[data-testid="history-event-evt-bad"]')
    expect(rejectedRow?.className).toContain('ev2-history__event--rejected')
    expect(rejectedRow?.textContent).toContain('Rejected')
    expect(rejectedRow?.textContent).toContain('ANCHOR_NOT_FOUND')

    const okRow = container.querySelector('[data-testid="history-event-evt-ok"]')
    expect(okRow?.className).not.toContain('ev2-history__event--rejected')
  })

  it('filters the list by actor text and by anchor selection', async () => {
    vi.mocked(fetchDocumentHistory).mockResolvedValue({
      events: [
        makeEvent({
          event_id: 'evt-alice',
          actor: 'alice',
          anchor: { heading_path: ['Intro'], ordinal: 0, block_id: 'blk-1' },
        }),
        makeEvent({
          event_id: 'evt-bob',
          actor: 'bob',
          anchor: { heading_path: ['Summary'], ordinal: 1, block_id: 'blk-2' },
        }),
      ],
      next_cursor: null,
    })

    await renderPanel()
    expect(eventRows()).toHaveLength(2)

    const actorInput = container.querySelector<HTMLInputElement>('input[aria-label="Filter by actor"]')
    expect(actorInput).toBeTruthy()
    act(() => {
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')!.set!
      setter.call(actorInput, 'ali')
      actorInput!.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(eventRows().map((r) => r.dataset.testid)).toEqual(['history-event-evt-alice'])

    // Reset actor filter, then filter by anchor instead.
    act(() => {
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')!.set!
      setter.call(actorInput, '')
      actorInput!.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(eventRows()).toHaveLength(2)

    const anchorSelect = container.querySelector<HTMLSelectElement>('select[aria-label="Filter by anchor"]')
    expect(anchorSelect).toBeTruthy()
    act(() => {
      const setter = Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype, 'value')!.set!
      setter.call(anchorSelect, 'Summary')
      anchorSelect!.dispatchEvent(new Event('change', { bubbles: true }))
    })
    expect(eventRows().map((r) => r.dataset.testid)).toEqual(['history-event-evt-bob'])
  })

  it('selecting one event shows the rewind pane; selecting a second swaps to the diff pane', async () => {
    vi.mocked(fetchDocumentHistory).mockResolvedValue({
      events: [
        makeEvent({ event_id: 'evt-1', ts: '2026-09-01T00:00:00Z', after_version: 2, after_hash: 'hash-a' }),
        makeEvent({ event_id: 'evt-2', ts: '2026-09-02T00:00:00Z', after_version: 3, after_hash: 'hash-b' }),
      ],
      next_cursor: null,
    })
    vi.mocked(fetchDocumentAtVersion).mockResolvedValue({
      content: 'hello',
      content_hash: 'hash-a',
      version: 2,
      reconstructed: true,
    })
    vi.mocked(fetchDocumentDiff).mockResolvedValue({
      from_version: 2,
      to_version: 3,
      from_hash: 'hash-a',
      to_hash: 'hash-b',
      diff: '@@ -1 +1 @@\n-old\n+new\n',
    })

    await renderPanel()

    act(() => {
      container.querySelector<HTMLButtonElement>('[data-testid="history-event-evt-1"]')?.click()
    })
    await flush()
    expect(container.querySelector('[data-testid="document-rewind-pane"]')).toBeTruthy()
    expect(container.querySelector('[data-testid="document-diff-pane"]')).toBeFalsy()

    act(() => {
      container.querySelector<HTMLButtonElement>('[data-testid="history-event-evt-2"]')?.click()
    })
    await flush()
    expect(container.querySelector('[data-testid="document-diff-pane"]')).toBeTruthy()
    expect(fetchDocumentDiff).toHaveBeenCalledWith(DOC_ID, PROJECT_ID, 2, 3)
  })
})

describe('DocumentHistoryEventRow', () => {
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  it('calls onSelect when clicked and reflects selected state via aria-pressed', () => {
    const onSelect = vi.fn()
    const event = makeEvent()
    act(() => {
      root.render(<DocumentHistoryEventRow event={event} selected={false} onSelect={onSelect} />)
    })
    const btn = container.querySelector<HTMLButtonElement>('[data-testid="history-event-evt-1"]')
    expect(btn?.getAttribute('aria-pressed')).toBe('false')
    act(() => btn?.click())
    expect(onSelect).toHaveBeenCalledTimes(1)

    act(() => {
      root.render(<DocumentHistoryEventRow event={event} selected onSelect={onSelect} />)
    })
    expect(
      container.querySelector<HTMLButtonElement>('[data-testid="history-event-evt-1"]')?.getAttribute('aria-pressed'),
    ).toBe('true')
  })
})

describe('DocumentRewindPane', () => {
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    vi.clearAllMocks()
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  async function flush() {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
  }

  it('shows the reconstructed pill and a hash-verified badge when hashes agree (client sha256 + server content_hash + event.after_hash)', async () => {
    const content = 'Historical body text.'
    const expectedHash = await sha256Hex(content)
    vi.mocked(fetchDocumentAtVersion).mockResolvedValue({
      content,
      content_hash: expectedHash,
      version: 2,
      reconstructed: true,
    })
    const event = makeEvent({ after_version: 2, after_hash: expectedHash })

    await act(async () => {
      root.render(<DocumentRewindPane documentId={DOC_ID} projectId={PROJECT_ID} event={event} />)
    })
    await flush()

    const pane = container.querySelector('[data-testid="document-rewind-pane"]')
    expect(pane?.textContent).toContain('reconstructed')
    expect(pane?.textContent).toContain('hash verified')
    expect(pane?.textContent).toContain('Historical body text.')
  })

  it('shows a hash-mismatch badge when the server content_hash disagrees with the event after_hash', async () => {
    const content = 'Tampered body.'
    vi.mocked(fetchDocumentAtVersion).mockResolvedValue({
      content,
      content_hash: 'server-hash',
      version: 2,
      reconstructed: true,
    })
    const event = makeEvent({ after_version: 2, after_hash: 'a-different-recorded-hash' })

    await act(async () => {
      root.render(<DocumentRewindPane documentId={DOC_ID} projectId={PROJECT_ID} event={event} />)
    })
    await flush()

    const pane = container.querySelector('[data-testid="document-rewind-pane"]')
    expect(pane?.textContent).toContain('hash mismatch')
  })
})

describe('DocumentDiffPane', () => {
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    vi.clearAllMocks()
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  async function flush() {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
  }

  it('renders unified diff lines with +/- styling, no external diff library', async () => {
    vi.mocked(fetchDocumentDiff).mockResolvedValue({
      from_version: 2,
      to_version: 3,
      from_hash: 'hash-a',
      to_hash: 'hash-b',
      diff: '@@ -1,2 +1,2 @@\n-removed line\n+added line\n context line',
    })

    await act(async () => {
      root.render(<DocumentDiffPane documentId={DOC_ID} projectId={PROJECT_ID} fromVersion={2} toVersion={3} />)
    })
    await flush()

    const pane = container.querySelector('[data-testid="document-diff-pane"]')
    expect(pane).toBeTruthy()
    const addLine = pane?.querySelector('.ev2-history__diff-line--add')
    const delLine = pane?.querySelector('.ev2-history__diff-line--del')
    expect(addLine?.textContent).toBe('+added line')
    expect(delLine?.textContent).toBe('-removed line')
    expect(pane?.textContent).toContain('v2')
    expect(pane?.textContent).toContain('v3')
  })

  it('surfaces a fetch failure as an error state', async () => {
    vi.mocked(fetchDocumentDiff).mockRejectedValue(new Error('boom'))

    await act(async () => {
      root.render(<DocumentDiffPane documentId={DOC_ID} projectId={PROJECT_ID} fromVersion={2} toVersion={3} />)
    })
    await flush()

    expect(container.querySelector('[data-testid="document-diff-error"]')?.textContent).toContain('boom')
  })
})
