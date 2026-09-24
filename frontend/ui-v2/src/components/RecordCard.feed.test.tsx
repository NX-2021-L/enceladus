import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RecordCard } from './RecordCard'
import { Badge } from './Badge'

/**
 * ENC-TSK-M35 -- smoke coverage for the dense "feed" RecordCard variant
 * (Enceladus-v4-Feed-Review.md §3/§4). No @testing-library/react in this
 * package (see SessionPrimitive.test.tsx) -- createRoot + act, matching the
 * rest of ui-v2's component-level tests.
 */
describe('RecordCard variant="feed"', () => {
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

  it('renders id, project, timestamp, single-line title, status and badges', () => {
    act(() => {
      root.render(
        <RecordCard
          recordId="ENC-TSK-M31"
          recordType="task"
          title="ISS-519 fix"
          status="in-progress"
          priority="P0"
          variant="feed"
          projectLabel="enceladus"
          timestamp="46m ago"
          accentColor="var(--enc-crimson)"
          badges={
            <>
              <Badge color="crimson">P0</Badge>
              <Badge color="amber">CHECKED OUT</Badge>
            </>
          }
        />,
      )
    })
    expect(container.textContent).toContain('ENC-TSK-M31')
    expect(container.textContent).toContain('enceladus')
    expect(container.textContent).toContain('46m ago')
    expect(container.textContent).toContain('ISS-519 fix')
    expect(container.textContent).toContain('in-progress')
    expect(container.textContent).toContain('P0')
    expect(container.textContent).toContain('CHECKED OUT')

    const titleEl = container.querySelector('.ev2-rc__feed-title')
    expect(titleEl).not.toBeNull()
  })

  it('applies the accent color as the left border', () => {
    act(() => {
      root.render(
        <RecordCard
          recordId="ENC-ISS-501"
          title="P0 SEV-1"
          status="open"
          priority="P0"
          variant="feed"
          accentColor="rgb(200, 80, 96)"
        />,
      )
    })
    const card = container.querySelector('.ev2-rc--feed') as HTMLElement
    expect(card).not.toBeNull()
    expect(card.style.borderLeftColor).toBe('rgb(200, 80, 96)')
  })

  it('is clickable via onSelect when no href is supplied (wide master-detail mode, FTR-128 AC-18)', () => {
    const onSelect = vi.fn()
    act(() => {
      root.render(
        <RecordCard
          recordId="ENC-TSK-M31"
          title="ISS-519 fix"
          status="open"
          variant="feed"
          onSelect={onSelect}
        />,
      )
    })
    const button = container.querySelector('button.ev2-rc--feed') as HTMLButtonElement
    expect(button).not.toBeNull()
    act(() => {
      button.click()
    })
    expect(onSelect).toHaveBeenCalledTimes(1)
  })
})
