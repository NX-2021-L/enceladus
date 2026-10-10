import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { DocumentSection } from './DocumentSection'
import type { DocumentSection as DocumentSectionModel } from '../utils/documentSections'

/**
 * No @testing-library/react is installed in this package (every existing
 * ui-v2 test is logic-level, not component-level) — createRoot + act,
 * matching src/primitives/SessionPrimitive.test.tsx.
 */

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

  it('renders the section body with the section key as its DOM id (AC-1 deep link target)', () => {
    act(() => {
      root.render(
        <DocumentSection section={makeSection()} changed={false} onEdit={vi.fn()} onAcknowledgeChange={vi.fn()} />,
      )
    })
    expect(document.getElementById('alpha-0')).toBeTruthy()
    expect(container.textContent).toContain('Alpha body text.')
  })

  it('calls onEdit when the Edit affordance is used', () => {
    const onEdit = vi.fn()
    act(() => {
      root.render(
        <DocumentSection section={makeSection()} changed={false} onEdit={onEdit} onAcknowledgeChange={vi.fn()} />,
      )
    })
    const editBtn = container.querySelector<HTMLButtonElement>('[aria-label="Edit section Alpha"]')
    expect(editBtn).toBeTruthy()
    act(() => {
      editBtn?.click()
    })
    expect(onEdit).toHaveBeenCalledTimes(1)
  })

  it('shows an Updated badge only when changed, and acknowledges on click', () => {
    const onAcknowledgeChange = vi.fn()
    act(() => {
      root.render(
        <DocumentSection
          section={makeSection()}
          changed
          onEdit={vi.fn()}
          onAcknowledgeChange={onAcknowledgeChange}
        />,
      )
    })
    const badge = Array.from(container.querySelectorAll('button')).find((b) => b.textContent === 'Updated')
    expect(badge).toBeTruthy()
    act(() => {
      badge?.click()
    })
    expect(onAcknowledgeChange).toHaveBeenCalledTimes(1)
  })

  it('omits the Updated badge when not changed', () => {
    act(() => {
      root.render(
        <DocumentSection section={makeSection()} changed={false} onEdit={vi.fn()} onAcknowledgeChange={vi.fn()} />,
      )
    })
    const badge = Array.from(container.querySelectorAll('button')).find((b) => b.textContent === 'Updated')
    expect(badge).toBeUndefined()
  })

  it('renders an empty-section placeholder when body is blank', () => {
    act(() => {
      root.render(
        <DocumentSection
          section={makeSection({ body: '' })}
          changed={false}
          onEdit={vi.fn()}
          onAcknowledgeChange={vi.fn()}
        />,
      )
    })
    expect(container.textContent).toContain('Empty section.')
  })
})
