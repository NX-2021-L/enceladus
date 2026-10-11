import { act, type ReactNode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { IndexRow } from '@io-kit/search'
import { mapCorpusItem } from '../search/corpusSource'

/**
 * DVP-TSK-995 AC: /feed renders the kit CollectionSearch -- exactly two rows before the results (R15: the search
 * input; Filter | Sort | Clear), the count in the header, NO header action -- with the existing record cards via
 * renderRow. No @testing-library in this package: createRoot + act.
 */
const navigate = vi.fn()
vi.mock('@tanstack/react-router', () => ({
  useSearch: () => ({ q: '', f: 'status|=|open', op: 'and', sort: 'updated', scroll: 0 }),
  useNavigate: () => navigate,
  Link: ({ children }: { children: ReactNode }) => <a>{children}</a>,
}))
vi.mock('../api/projectRegistry', () => ({
  projectRegistryQueryOptions: { queryKey: ['test-projects'], queryFn: async () => [] },
  resolveProjectFromRecordId: () => null,
}))
vi.mock('../routes/FeedReadingPane', () => ({ FeedReadingPane: () => null }))
vi.mock('../routes/RecentlyViewedNav', () => ({ RecentlyViewedNav: () => null }))

const rows: IndexRow[] = [1, 2, 3].map(
  (n) =>
    mapCorpusItem({
      record_id: `ENC-TSK-${n}`, record_type: 'task', project_id: 'enceladus', title: `Task ${n}`, updated_at: `2026-10-0${n}T00:00:00Z`,
      source: 'tracker', record_key: `tracker:enceladus:ENC-TSK-${n}`, version_seq: n, attrs: { status: n === 3 ? 'closed' : 'open' },
    })!,
)
vi.mock('../search/CorpusProvider', () => ({
  useEnceladusCorpus: () => ({ rows, status: 'live', lastSeededAt: null, staleNotice: null, error: null, refresh: async () => {} }),
}))

describe('/feed on the kit CollectionSearch', () => {
  let container: HTMLDivElement
  let root: Root
  beforeEach(() => {
    window.matchMedia = vi.fn().mockImplementation((query: string) => ({
      matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    })) as unknown as typeof window.matchMedia
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })
  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  it('renders two rows, the count in the header, no header action, and the existing cards', async () => {
    const { default: FeedSearchPage } = await import('./FeedSearchPage')
    await act(async () => {
      root.render(
        <QueryClientProvider client={new QueryClient()}>
          <FeedSearchPage />
        </QueryClientProvider>,
      )
    })
    const section = container.querySelector('section[data-io-search]')!
    expect(section).toBeTruthy()
    expect(container.querySelectorAll('.io-search__row1')).toHaveLength(1)
    const row2 = container.querySelector('.io-search__row2')!
    expect(row2.children).toHaveLength(3) // Filter | Sort | Clear
    expect(row2.textContent).toMatch(/Filter \(1\)/)
    expect(row2.textContent).toMatch(/Updated/)
    expect(row2.textContent).toMatch(/Clear/)
    // header: title + count, and no action control
    // R16: the page header (title + count) lives in the SplitPage header slot, above the columns.
    const header = container.querySelector('.io-split__header [data-page-header]')!
    expect(header.textContent).toMatch(/Feed/)
    expect(header.textContent).toMatch(/\(2\)/) // status=open -> 2 of 3 rows
    // DVP-TSK-A12: the only header control is the tiny "hide toggles" link (no action button)
    expect([...header.querySelectorAll('button')].map((b) => b.textContent)).toEqual(['hide toggles'])
    expect(container.textContent).not.toMatch(/Pin as related/)
    // results are the existing record cards (status=open filter from the old-style URL applied)
    const results = container.querySelectorAll('.io-search__results > li')
    expect(results).toHaveLength(2)
    expect(results[0]!.textContent).toContain('ENC-TSK-2')
    // the old two-box toolbar and pill filter are gone
    expect(container.querySelector('.feed-route__toolbar')).toBeNull()
  }, 30_000)

  it('puts "hide toggles" right after the count, hides the control block, and persists it under the feed key', async () => {
    const storageKey = 'io-search:controls:feed'
    sessionStorage.removeItem(storageKey)
    const { default: FeedSearchPage } = await import('./FeedSearchPage')
    await act(async () => {
      root.render(
        <QueryClientProvider client={new QueryClient()}>
          <FeedSearchPage />
        </QueryClientProvider>,
      )
    })
    try {
      const header = container.querySelector('.io-split__header [data-page-header]')!
      const toggle = header.querySelector('button.io-search__controls-toggle') as HTMLButtonElement
      expect(toggle.textContent).toBe('hide toggles')
      // in the title row, directly after the muted count
      expect(toggle.closest('.ev2-page-header__meta')!.previousElementSibling!.classList.contains('ev2-header__counter')).toBe(true)
      // one toggle only: CollectionSearch's own header link is off
      expect(container.querySelectorAll('.io-search__controls-toggle')).toHaveLength(1)
      const controls = container.querySelector('.io-search__controls') as HTMLElement
      expect(controls.id).not.toBe('')
      expect(toggle.getAttribute('aria-controls')).toBe(controls.id)
      expect(toggle.getAttribute('aria-expanded')).toBe('true')
      expect(controls.hidden).toBe(false)
      await act(async () => {
        toggle.click()
      })
      expect(toggle.textContent).toBe('show toggles')
      expect(toggle.getAttribute('aria-expanded')).toBe('false')
      expect(controls.hidden).toBe(true)
      expect(sessionStorage.getItem(storageKey)).toBe('1')
    } finally {
      sessionStorage.removeItem(storageKey)
    }
  }, 30_000)
})
