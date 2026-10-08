import { act, type ReactNode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CacheEngineProvider } from '../sync/CacheEngineProvider'
import { getCacheEngine, resetCacheEngineForTests } from '../sync/cacheEngine'
import { seedCacheFromCorpus } from '../sync/corpusSeed'
import type { FeedCorpusItem } from '../sync/types'
import { DocsRoute } from './DocsRoute'

/**
 * ENC-TSK-Q33 (ENC-ISS-830) AC-3/AC-4: /docs must repaint when the corpus
 * seed lands on top of a pre-warmed IndexedDB slice, and must say so when the
 * seed fails. No @testing-library/react in this package: createRoot + act.
 */

vi.mock('@tanstack/react-router', () => ({
  useSearch: () => ({}),
  Link: ({ children, className }: { children: ReactNode; className?: string }) => (
    <a className={className}>{children}</a>
  ),
}))

// A STABLE events array, as in the app between realtime batches: a fresh []
// per render would invalidate React Compiler memoization and hide the bug.
const NO_EVENTS: never[] = []
vi.mock('../realtime/RealtimeFeedProvider', () => ({
  useRealtimeFeedEvents: () => NO_EVENTS,
}))

vi.mock('../api/projectRegistry', () => ({
  projectRegistryQueryOptions: { queryKey: ['test-projects'], queryFn: async () => [] },
  resolveProjectFromRecordId: () => null,
}))

vi.mock('../sync/queryPersist', () => ({
  restorePersistedQueryClient: async () => {},
  attachQueryClientPersist: () => () => {},
}))

vi.mock('../sync/corpusSeed', () => ({
  seedCacheFromCorpus: vi.fn(),
}))

function docItem(recordId: string, title: string, updatedAt: string): FeedCorpusItem {
  return {
    record_id: recordId,
    record_type: 'document',
    project_id: 'devops',
    title,
    updated_at: updatedAt,
    source: 'document',
    record_key: `document::${recordId}`,
    attrs: { status: 'active' },
  }
}

const STALE_DOC = docItem('DOC-84D804007721', 'Travel doc (stale newest)', '2026-10-01T19:13:52Z')
const NEW_DOC = docItem('DOC-2F56AACDD5C0', 'Fresh devops doc', '2026-10-08T02:29:33Z')

let root: Root | null = null
let container: HTMLDivElement | null = null

async function flush(): Promise<void> {
  for (let i = 0; i < 10; i += 1) {
    await act(async () => {
      await Promise.resolve()
    })
  }
}

function cardTitles(): string[] {
  return [...(container?.querySelectorAll('.docs-route__card-link') ?? [])].map((el) => el.textContent ?? '')
}

async function renderDocs(): Promise<void> {
  container = document.createElement('div')
  document.body.appendChild(container)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  await act(async () => {
    root = createRoot(container!)
    root.render(
      <QueryClientProvider client={client}>
        <CacheEngineProvider>
          <DocsRoute />
        </CacheEngineProvider>
      </QueryClientProvider>,
    )
  })
  await flush()
}

describe('DocsRoute over a stale IndexedDB slice (ENC-TSK-Q33)', () => {
  beforeEach(async () => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    resetCacheEngineForTests()
    vi.mocked(seedCacheFromCorpus).mockReset()
    // The previous visit left only the 10-01 doc in IndexedDB.
    await getCacheEngine().ingestCorpusPage([STALE_DOC])
    resetCacheEngineForTestsKeepingIdb()
  })

  afterEach(() => {
    act(() => root?.unmount())
    container?.remove()
    root = null
    container = null
    vi.useRealTimers()
  })

  it('repaints with the newer document first once the seed completes, with no other state change', async () => {
    let releaseSeed: () => void = () => {}
    vi.mocked(seedCacheFromCorpus).mockImplementation(async () => {
      await new Promise<void>((resolve) => {
        releaseSeed = resolve
      })
      const engine = getCacheEngine()
      await engine.ingestCorpusPage([STALE_DOC, NEW_DOC])
      await engine.finalizeWarm()
      return { pages: 1, records: 2, durationMs: 1 }
    })

    await renderDocs()
    expect(cardTitles()).toEqual(['Travel doc (stale newest)'])

    await act(async () => {
      releaseSeed()
    })
    await flush()

    expect(cardTitles()).toEqual(['Fresh devops doc', 'Travel doc (stale newest)'])
    expect(container?.textContent).toContain('2 documents')
    expect(container?.textContent).not.toContain('may be out of date')
  })

  it('shows a non-blocking stale notice with the last refresh time when the seed fails', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    vi.mocked(seedCacheFromCorpus).mockRejectedValue(new Error('Request failed (502): /api/v1/feed/corpus'))

    await renderDocs()
    await act(async () => {
      await vi.runAllTimersAsync()
    })
    await flush()

    expect(container?.textContent).toContain('Documents may be out of date')
    expect(container?.textContent).toContain('The live refresh failed: Request failed (502)')
    expect(container?.textContent).toContain('never completed a live refresh')
    // The cached list still renders under the notice.
    expect(cardTitles()).toEqual(['Travel doc (stale newest)'])
  })
})

/** Drop the in-memory engine singleton (search index, warm flag) but keep the
 *  memory IndexedDB rows, simulating a fresh page load over a persisted slice. */
function resetCacheEngineForTestsKeepingIdb(): void {
  const engine = getCacheEngine() as unknown as { warmedAt: number | null }
  engine.warmedAt = null
  getCacheEngine().searchIndex.rebuild([])
}
