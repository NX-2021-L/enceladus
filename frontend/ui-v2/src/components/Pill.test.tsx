import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { CheckoutChip, ComponentChips, PriorityChip, SeverityChip } from './ChipRow'
import { OpChip, Tag, UrgencyBadge, isCheckedOut, urgencyLevel } from './Pill'

describe('urgencyLevel (spec 4.5: one neutral scale for priority, severity, gate risk)', () => {
  it('maps P0-P3 and critical-low to levels 0-3', () => {
    expect(['P0', 'P1', 'P2', 'P3'].map(urgencyLevel)).toEqual([0, 1, 2, 3])
    expect(['critical', 'high', 'medium', 'low'].map(urgencyLevel)).toEqual([0, 1, 2, 3])
    expect(urgencyLevel(' p0 ')).toBe(0)
    expect(urgencyLevel('unknown')).toBe(3)
    expect(urgencyLevel(undefined)).toBe(3)
  })
})

describe('pill family rendering', () => {
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

  it('draws priority the same way on the feed (UrgencyBadge) and on the detail page (PriorityChip)', () => {
    act(() => root.render(<><UrgencyBadge value="p1" /><PriorityChip priority="P1" /></>))
    const badges = container.querySelectorAll('.enc-badge')
    expect(badges).toHaveLength(2)
    expect([...badges].map((b) => [b.getAttribute('data-level'), b.textContent])).toEqual([
      ['1', 'P1'],
      ['1', 'P1'],
    ])
  })

  it('severity uses the urgency badge, not a status hue', () => {
    act(() => root.render(<SeverityChip severity="critical" />))
    expect(container.querySelector('.enc-badge')?.getAttribute('data-level')).toBe('0')
  })

  it('checkout is an operational chip: held or free', () => {
    act(() => root.render(<><CheckoutChip checkedOut /><CheckoutChip checkedOut={false} /><OpChip op="session">Active</OpChip></>))
    expect([...container.querySelectorAll('.enc-op')].map((e) => e.getAttribute('data-op'))).toEqual(['held', 'free', 'session'])
    expect(isCheckedOut('checked_out')).toBe(true)
    expect(isCheckedOut('checked_in')).toBe(false)
  })

  it('components are code tags; document types carry data-doctype', () => {
    act(() => root.render(<><ComponentChips components={['comp-enceladus-pwa']} /><Tag doctype="BRD">brd</Tag></>))
    const tags = container.querySelectorAll('.enc-tag')
    expect(tags[0].getAttribute('data-kind')).toBe('code')
    expect(tags[1].getAttribute('data-doctype')).toBe('brd')
  })

  it('renders nothing for a missing urgency value', () => {
    act(() => root.render(<UrgencyBadge value={null} />))
    expect(container.innerHTML).toBe('')
  })
})
