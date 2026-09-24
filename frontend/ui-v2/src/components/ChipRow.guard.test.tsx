/**
 * ENC-TSK-P60 (ENC-ISS-714) — ChipRow tolerates string/null list fields.
 * A corpus record whose `components` reached the client as a plain string
 * passed the old truthiness guard (strings have .length) and crashed the
 * whole Feed at `components.map`. createRoot + act pattern per
 * SessionPrimitive.test.tsx (no @testing-library/react in this package).
 */
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { ComponentChips } from './ChipRow'

describe('ComponentChips guard (ENC-TSK-P60)', () => {
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

  it('renders normally for an array', () => {
    act(() => {
      root.render(<ComponentChips components={['frontend', 'comp-devops-governance']} />)
    })
    expect(container.textContent).toContain('frontend')
    expect(container.textContent).toContain('comp-devops-governance')
  })

  it('does NOT crash on a string — renders it as a single chip', () => {
    act(() => {
      root.render(<ComponentChips components={'frontend' as unknown as string[]} />)
    })
    expect(container.textContent).toContain('frontend')
  })

  it('renders nothing for null/undefined/empty-string', () => {
    act(() => {
      root.render(<ComponentChips components={null as unknown as string[]} />)
    })
    expect(container.textContent).toBe('')
    act(() => {
      root.render(<ComponentChips components={'   ' as unknown as string[]} />)
    })
    expect(container.textContent).toBe('')
  })
})
