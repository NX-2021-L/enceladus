import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { DocumentSection } from './DocumentSection'
import type { DocumentSection as DocumentSectionModel } from '../../lib/documentSections'

function makeSection(overrides: Partial<DocumentSectionModel> = {}): DocumentSectionModel {
  return {
    entry: {
      heading_path: ['Alpha'],
      level: 2,
      ordinal: 0,
      block_id: null,
      line_start: 0,
      line_end: 0,
      section_bytes: 0,
    },
    key: 'alpha-0',
    headingText: 'Alpha',
    body: 'Alpha body text.',
    ...overrides,
  }
}

describe('DocumentSection', () => {
  it('renders the section body with the section key as its DOM id (AC-1 deep link target)', () => {
    render(
      <DocumentSection section={makeSection()} changed={false} onEdit={vi.fn()} onAcknowledgeChange={vi.fn()} />,
    )
    expect(document.getElementById('alpha-0')).toBeInTheDocument()
    expect(screen.getByText('Alpha body text.')).toBeInTheDocument()
  })

  it('calls onEdit when the Edit affordance is used', async () => {
    const onEdit = vi.fn()
    const user = userEvent.setup()
    render(
      <DocumentSection section={makeSection()} changed={false} onEdit={onEdit} onAcknowledgeChange={vi.fn()} />,
    )
    await user.click(screen.getByRole('button', { name: /edit section alpha/i }))
    expect(onEdit).toHaveBeenCalledTimes(1)
  })

  it('shows an Updated badge only when changed, and acknowledges on click', async () => {
    const onAcknowledgeChange = vi.fn()
    const user = userEvent.setup()
    render(
      <DocumentSection
        section={makeSection()}
        changed
        onEdit={vi.fn()}
        onAcknowledgeChange={onAcknowledgeChange}
      />,
    )
    const badge = screen.getByRole('button', { name: /updated/i })
    await user.click(badge)
    expect(onAcknowledgeChange).toHaveBeenCalledTimes(1)
  })

  it('omits the Updated badge when not changed', () => {
    render(
      <DocumentSection section={makeSection()} changed={false} onEdit={vi.fn()} onAcknowledgeChange={vi.fn()} />,
    )
    expect(screen.queryByRole('button', { name: /updated/i })).not.toBeInTheDocument()
  })

  it('renders an empty-section placeholder when body is blank', () => {
    render(
      <DocumentSection
        section={makeSection({ body: '' })}
        changed={false}
        onEdit={vi.fn()}
        onAcknowledgeChange={vi.fn()}
      />,
    )
    expect(screen.getByText(/empty section/i)).toBeInTheDocument()
  })
})
