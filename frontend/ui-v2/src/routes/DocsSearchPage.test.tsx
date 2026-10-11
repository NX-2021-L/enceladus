import { act, type ReactNode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mapCorpusItem } from '../search/corpusSource'

/** DVP-TSK-995: /docs is the same CollectionSearch, scoped to the document sequence space (record_type=document). */
vi.mock('@tanstack/react-router', () => ({
  useSearch: () => ({ project: 'devops' }),
  Link: ({ children }: { children: ReactNode }) => <a>{children}</a>,
}))
vi.mock('../api/projectRegistry', () => ({
  projectRegistryQueryOptions: { queryKey: ['test-projects'], queryFn: async () => [] },
  resolveProjectFromRecordId: () => null,
}))
const base = { project_id: 'devops', updated_at: '2026-10-01T00:00:00Z', version_seq: 1 }
const rows = [
  mapCorpusItem({ ...base, record_id: 'DOC-A', record_type: 'document', title: 'Alpha doc', source: 'document', record_key: 'document::DOC-A' })!,
  mapCorpusItem({ ...base, record_id: 'DOC-B', record_type: 'document', title: 'Beta doc', source: 'document', record_key: 'document::DOC-B', project_id: 'enceladus' })!,
  mapCorpusItem({ ...base, record_id: 'DVP-TSK-1', record_type: 'task', title: 'A task', source: 'tracker', record_key: 'tracker:devops:DVP-TSK-1' })!,
]
vi.mock('../search/CorpusProvider', () => ({
  useEnceladusCorpus: () => ({ rows, status: 'live', lastSeededAt: null, staleNotice: null, error: null, refresh: async () => {} }),
}))

describe('/docs on the kit CollectionSearch', () => {
  let container: HTMLDivElement
  let root: Root
  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    window.matchMedia = vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })) as unknown as typeof window.matchMedia
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })
  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  it('lists documents only and seeds ?project= as a visible filter', async () => {
    const { default: DocsSearchPage } = await import('./DocsSearchPage')
    await act(async () => {
      root.render(
        <QueryClientProvider client={new QueryClient()}>
          <DocsSearchPage />
        </QueryClientProvider>,
      )
    })
    const section = container.querySelector('section[data-io-search]')!
    expect(section.firstElementChild!.textContent).toMatch(/Documents.*\(1\)/) // project_id=devops narrows 2 docs to 1
    const results = [...container.querySelectorAll('.io-search__results > li')]
    expect(results.map((li) => li.textContent).join(' ')).toContain('DOC-A')
    expect(results.map((li) => li.textContent).join(' ')).not.toContain('DVP-TSK-1')
    expect(container.querySelector('.io-search__row2')!.textContent).toMatch(/Filter \(1\)/)
  }, 30_000)
})
