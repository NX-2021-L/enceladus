import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { Document } from '../types/records'
import type { DocumentManifest, DocumentOutlineEntry } from '../api/documentManifest'
import type { FeedRealtimeEvent } from '../types/feedEvents'

/**
 * No @testing-library/react is installed in this package (every existing
 * ui-v2 test is logic-level, not component-level) — createRoot + act,
 * matching src/hooks/useRecordMutation.test.tsx (the established pattern for
 * async mutation flows in this package).
 */

vi.mock('../api/documentManifest', async () => {
  const actual = await vi.importActual<typeof import('../api/documentManifest')>('../api/documentManifest')
  return { ...actual, fetchDocumentManifest: vi.fn() }
})
vi.mock('../api/documentSections', async () => {
  const actual = await vi.importActual<typeof import('../api/documentSections')>('../api/documentSections')
  return { ...actual, patchSection: vi.fn() }
})
vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return { ...actual, fetchDocumentRecord: vi.fn() }
})

let liveCallback: ((event: FeedRealtimeEvent) => void) | null = null
vi.mock('../realtime/RealtimeFeedProvider', () => ({
  useRealtimeFeed: () => ({
    watchRecord: (_recordId: string, onEvent: (event: FeedRealtimeEvent) => void) => {
      liveCallback = onEvent
      return () => {
        liveCallback = null
      }
    },
  }),
}))

import { fetchDocumentManifest } from '../api/documentManifest'
import { patchSection, SectionPatchError } from '../api/documentSections'
import { fetchDocumentRecord } from '../api/client'
import { DocumentSectionsView } from './DocumentSectionsView'

const DOC_ID = 'DOC-TEST01'
const PROJECT_ID = 'enceladus'

const BODY = [
  '# Doc Title',
  '',
  '## First',
  '',
  'First body.',
  '',
  '## Second',
  '',
  'Second body.',
  '',
].join('\n')

function outlineEntry(overrides: Partial<DocumentOutlineEntry>): DocumentOutlineEntry {
  return {
    heading_path: ['First'],
    level: 2,
    ordinal: 0,
    block_id: null,
    line_start: 0,
    line_end: 0,
    section_bytes: 0,
    ...overrides,
  }
}

const FIRST_ENTRY = outlineEntry({ heading_path: ['First'], ordinal: 0 })
const SECOND_ENTRY = outlineEntry({ heading_path: ['Second'], ordinal: 1 })

function makeManifest(overrides: Partial<DocumentManifest> = {}): DocumentManifest {
  return {
    document_id: DOC_ID,
    project_id: PROJECT_ID,
    title: 'Test Doc',
    version: 1,
    content_hash: 'hash-v1',
    size_bytes: BODY.length,
    updated_at: '2026-09-01T00:00:00Z',
    // Matches BODY's two real headings — an outline entry list shorter than
    // the body's actual headings makes the last declared entry's slice run
    // to end-of-document (no next-entry bound), which is exactly what the
    // AC-4 test below exploits intentionally; every other test wants both
    // sections cleanly bounded, so the default lists both.
    outline: [FIRST_ENTRY, SECOND_ENTRY],
    ...overrides,
  }
}

const RECORD: Document = {
  document_id: DOC_ID,
  project_id: PROJECT_ID,
  title: 'Test Doc',
  description: '',
  file_name: 'test.md',
  content_type: 'text/markdown',
  keywords: [],
  related_items: [],
  status: 'active',
  created_by: 'tester',
  created_at: '2026-09-01T00:00:00Z',
  updated_at: '2026-09-01T00:00:00Z',
  version: 1,
  content: BODY,
  content_hash: 'hash-v1',
}

function makeEvent(overrides: Partial<FeedRealtimeEvent> = {}): FeedRealtimeEvent {
  return {
    eventId: 'evt-1',
    recordId: DOC_ID,
    record_type: 'document',
    action: 'updated',
    actorType: 'human',
    actorId: 'someone-else',
    summary: 'edited elsewhere',
    cursor: 1,
    channels: [`/records/${DOC_ID}`],
    ...overrides,
  }
}

describe('DocumentSectionsView', () => {
  let qc: QueryClient
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    liveCallback = null
    vi.clearAllMocks()
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
    qc.clear()
  })

  // TanStack Query's observer notification goes through notifyManager,
  // which (in this jsdom/vitest setup) needs at least one real macrotask
  // tick to flush — plain chained `await Promise.resolve()` microtasks are
  // not enough to observe a resolved queryFn's effect on the DOM.
  async function flush(times = 2) {
    for (let i = 0; i < times; i++) {
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 0))
      })
    }
  }

  async function renderView(record: Document = RECORD) {
    await act(async () => {
      root.render(
        <QueryClientProvider client={qc}>
          <DocumentSectionsView record={record} />
        </QueryClientProvider>,
      )
    })
    await flush()
  }

  it('renders the manifest-driven outline tree and per-section bodies before/independent of whole-body rendering (AC-1)', async () => {
    vi.mocked(fetchDocumentManifest).mockResolvedValue(makeManifest())
    await renderView()

    expect(container.querySelector('nav[aria-label="Document outline"]')).toBeTruthy()
    expect(container.textContent).toContain('First')
    expect(document.getElementById('first-0')).toBeTruthy()
    expect(container.textContent).toContain('First body.')
  })

  it('opens a markdown editor scoped to the clicked section, defaulting the advanced toggles to the server defaults (AC-2)', async () => {
    vi.mocked(fetchDocumentManifest).mockResolvedValue(makeManifest())
    await renderView()

    const editBtn = container.querySelector<HTMLButtonElement>('[aria-label="Edit section First"]')
    expect(editBtn).toBeTruthy()
    act(() => {
      editBtn?.click()
    })

    const dialog = container.querySelector('[role="dialog"]')
    expect(dialog).toBeTruthy()
    const textarea = container.querySelector<HTMLTextAreaElement>('textarea')
    expect(textarea?.value).toBe('First body.')

    const checkboxes = Array.from(container.querySelectorAll<HTMLInputElement>('input[type="checkbox"]'))
    expect(checkboxes).toHaveLength(2)
    // include_heading defaults false, rebase_headings defaults true.
    expect(checkboxes[0].checked).toBe(false)
    expect(checkboxes[1].checked).toBe(true)

    act(() => {
      // React tracks a controlled input's previous value on the DOM node
      // itself; setting `.value` directly leaves that tracker stale, so the
      // native setter must be used for the subsequent 'input' event to reach
      // the component's onChange (same trick @testing-library/user-event
      // uses under the hood).
      const nativeSetter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype,
        'value',
      )!.set!
      nativeSetter.call(textarea, 'Updated first body.')
      textarea!.dispatchEvent(new Event('input', { bubbles: true }))
    })

    vi.mocked(patchSection).mockResolvedValue({
      document_id: DOC_ID,
      version: 2,
      content_hash: 'hash-v2',
      size_bytes: 10,
      event_id: 'evt-save',
      anchor_resolved: { heading_path: ['First'], level: 2, ordinal: 0, block_id: null },
      bytes_changed: 5,
      outline: [FIRST_ENTRY],
    })

    const saveBtn = Array.from(container.querySelectorAll('button')).find((b) => b.textContent === 'Save')
    act(() => {
      saveBtn?.click()
    })
    await flush()

    expect(patchSection).toHaveBeenCalledWith(
      DOC_ID,
      expect.objectContaining({
        document_id: DOC_ID,
        project_id: PROJECT_ID,
        anchor: { heading_path: ['First'], ordinal: 0 },
        op: 'replace',
        body: 'Updated first body.',
        if_match: 'hash-v1',
        include_heading: false,
        rebase_headings: true,
      }),
    )
    // Editor closes on a successful save.
    expect(container.querySelector('[role="dialog"]')).toBeFalsy()
  })

  it('opens a side-by-side conflict view on 412 CONTENT_HASH_MISMATCH, with re-apply/discard and no automatic write (AC-3)', async () => {
    vi.mocked(fetchDocumentManifest)
      .mockResolvedValueOnce(makeManifest())
      .mockResolvedValueOnce(makeManifest({ content_hash: 'hash-v2' }))
    vi.mocked(fetchDocumentRecord).mockResolvedValue({
      content: BODY.replace('First body.', 'First body EDITED remotely.'),
    })
    vi.mocked(patchSection).mockRejectedValue(
      new SectionPatchError(412, 'CONTENT_HASH_MISMATCH', 'stale', {
        current_hash: 'hash-v2',
        current_version: 2,
      }),
    )

    await renderView()
    act(() => {
      container.querySelector<HTMLButtonElement>('[aria-label="Edit section First"]')?.click()
    })

    const saveBtn = Array.from(container.querySelectorAll('button')).find((b) => b.textContent === 'Save')
    act(() => {
      saveBtn?.click()
    })
    await flush()

    expect(container.textContent).toContain('Conflict')
    expect(container.textContent).toContain('First body.') // your edit, unchanged
    expect(container.textContent).toContain('First body EDITED remotely.') // current stored
    expect(patchSection).toHaveBeenCalledTimes(1) // no automatic merge/write

    const reapplyBtn = Array.from(container.querySelectorAll('button')).find(
      (b) => b.textContent === 'Re-apply my edit',
    )
    act(() => {
      reapplyBtn?.click()
    })

    // Back to the plain editor — draft preserved, if_match rebased, still no write.
    expect(container.querySelector('textarea')?.value).toBe('First body.')
    expect(patchSection).toHaveBeenCalledTimes(1)
  })

  it('discards the draft and closes the editor via the conflict view Discard action (AC-3)', async () => {
    vi.mocked(fetchDocumentManifest)
      .mockResolvedValueOnce(makeManifest())
      .mockResolvedValueOnce(makeManifest({ content_hash: 'hash-v2' }))
    vi.mocked(fetchDocumentRecord).mockResolvedValue({ content: BODY })
    vi.mocked(patchSection).mockRejectedValue(
      new SectionPatchError(412, 'CONTENT_HASH_MISMATCH', 'stale', { current_hash: 'hash-v2' }),
    )

    await renderView()
    act(() => {
      container.querySelector<HTMLButtonElement>('[aria-label="Edit section First"]')?.click()
    })
    const saveBtn = Array.from(container.querySelectorAll('button')).find((b) => b.textContent === 'Save')
    act(() => {
      saveBtn?.click()
    })
    await flush()
    expect(container.textContent).toContain('Conflict')

    const discardBtn = Array.from(container.querySelectorAll('button')).find(
      (b) => b.textContent === 'Discard my edit',
    )
    act(() => {
      discardBtn?.click()
    })
    expect(container.querySelector('[role="dialog"]')).toBeFalsy()
    expect(patchSection).toHaveBeenCalledTimes(1)
  })

  it('marks a newly-surfaced section changed after a live mutation refetches the manifest, and keeps an open editor\'s if_match untouched (AC-4)', async () => {
    vi.mocked(fetchDocumentManifest)
      .mockResolvedValueOnce(makeManifest({ outline: [FIRST_ENTRY] }))
      .mockResolvedValueOnce(makeManifest({ outline: [FIRST_ENTRY, SECOND_ENTRY], content_hash: 'hash-v2' }))

    await renderView()
    // Only one outline entry exists yet, so Second has no section card of
    // its own — its raw text is present (swallowed into First's unbounded
    // tail slice, since there's no next entry to stop at), so the assertion
    // targets the section CARD, not substring text.
    expect(container.querySelector('[data-testid="document-section-second-1"]')).toBeFalsy()

    // Open the editor on First BEFORE the live event lands.
    act(() => {
      container.querySelector<HTMLButtonElement>('[aria-label="Edit section First"]')?.click()
    })
    expect(container.querySelector<HTMLTextAreaElement>('textarea')).toBeTruthy()

    expect(liveCallback).toBeTruthy()
    act(() => {
      liveCallback?.(makeEvent())
    })
    await flush()

    // Outline refreshed: Second now has its own section card and is marked changed.
    expect(container.querySelector('[data-testid="document-section-second-1"]')).toBeTruthy()
    const updatedBadges = Array.from(container.querySelectorAll('button')).filter(
      (b) => b.textContent === 'Updated',
    )
    expect(updatedBadges.length).toBeGreaterThan(0)

    // The open editor surfaces a banner rather than silently swapping if_match.
    expect(container.textContent).toContain('changed elsewhere while you were editing')

    vi.mocked(patchSection).mockResolvedValue({
      document_id: DOC_ID,
      version: 3,
      content_hash: 'hash-v3',
      size_bytes: 10,
      event_id: 'evt-save-2',
      anchor_resolved: { heading_path: ['First'], level: 2, ordinal: 0, block_id: null },
      bytes_changed: 1,
      outline: [FIRST_ENTRY, SECOND_ENTRY],
    })
    const saveBtn = Array.from(container.querySelectorAll('button')).find((b) => b.textContent === 'Save')
    act(() => {
      saveBtn?.click()
    })
    await flush()

    // The save still went out with the ORIGINALLY captured if_match, not the
    // refreshed hash-v2 — the live refresh never silently replaced it.
    expect(patchSection).toHaveBeenCalledWith(DOC_ID, expect.objectContaining({ if_match: 'hash-v1' }))
  })
})
