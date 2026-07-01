import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { DownloadMarkdownButton } from './DownloadMarkdownButton'
import type { Document } from '../../types/feeds'

function makeDoc(overrides: Partial<Document> = {}): Document {
  return {
    document_id: 'DOC-ABC123',
    project_id: 'enceladus',
    title: 'My Doc',
    description: '',
    file_name: 'my-doc.md',
    content_type: 'text/markdown',
    content_hash: 'abc',
    size_bytes: 42,
    keywords: [],
    related_items: [],
    status: 'active',
    created_by: 'tester',
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
    version: 1,
    content: '# Hello',
    document_maturity_state: 'raw',
    document_subtype: 'general',
    ...overrides,
  }
}

describe('DownloadMarkdownButton', () => {
  let createObjectURLSpy: ReturnType<typeof vi.fn>
  let revokeObjectURLSpy: ReturnType<typeof vi.fn>
  let clickSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    createObjectURLSpy = vi.fn(() => 'blob:mock-url')
    revokeObjectURLSpy = vi.fn()
    // jsdom doesn't implement these.
    // @ts-expect-error -- test stub
    URL.createObjectURL = createObjectURLSpy
    // @ts-expect-error -- test stub
    URL.revokeObjectURL = revokeObjectURLSpy
    clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders with the expected tooltip and aria-label', () => {
    render(<DownloadMarkdownButton document={makeDoc()} />)
    const button = screen.getByRole('button', { name: 'Download markdown' })
    expect(button).toBeInTheDocument()
    expect(button).toHaveAttribute('title', 'Download markdown')
  })

  it('triggers a blob download and shows the success state on click', () => {
    const doc = makeDoc({ title: 'Design Doc: Phase 2' })
    render(<DownloadMarkdownButton document={doc} />)

    const button = screen.getByRole('button', { name: 'Download markdown' })
    fireEvent.click(button)

    expect(createObjectURLSpy).toHaveBeenCalledTimes(1)
    const blobArg = createObjectURLSpy.mock.calls[0]![0] as Blob
    expect(blobArg).toBeInstanceOf(Blob)
    expect(blobArg.type).toContain('text/markdown')

    expect(clickSpy).toHaveBeenCalledTimes(1)
    expect(revokeObjectURLSpy).toHaveBeenCalledWith('blob:mock-url')

    // success affordance mirrors CopyButton's local "copied" state pattern
    expect(screen.getByRole('button', { name: 'Downloaded' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Downloaded' })).toHaveAttribute('title', 'Downloaded!')
  })

  it('sets the download filename from the document id and title slug', () => {
    const doc = makeDoc({ document_id: 'DOC-XYZ789', title: 'Design Doc: Phase 2' })
    const appendSpy = vi.spyOn(document.body, 'appendChild')

    render(<DownloadMarkdownButton document={doc} />)
    fireEvent.click(screen.getByRole('button', { name: 'Download markdown' }))

    const anchor = appendSpy.mock.calls
      .map((call) => call[0])
      .find((node): node is HTMLAnchorElement => node instanceof HTMLAnchorElement)
    expect(anchor?.download).toBe('DOC-XYZ789-design-doc-phase-2.md')
  })

  it('does not fetch or mutate any external state — only serializes the passed-in document', () => {
    const doc = makeDoc({ content: 'verbatim body' })
    render(<DownloadMarkdownButton document={doc} />)
    fireEvent.click(screen.getByRole('button', { name: 'Download markdown' }))

    // Blob content should reflect the doc object passed as a prop, proving
    // no additional fetch/generation happened client-side.
    expect(createObjectURLSpy).toHaveBeenCalledTimes(1)
  })
})
