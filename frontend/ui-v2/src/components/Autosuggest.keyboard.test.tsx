/**
 * ENC-TSK-P57 — Autosuggest keyboard operation + combobox ARIA.
 *
 * The Autosuggest design-system component backs every suggestion-rendering
 * search input in the PWA (Feed search, Docs search, and the attribute-filter
 * composer on both routes), so the keyboard contract is pinned here once:
 *   - ArrowDown/ArrowUp move the active option (wrapping past either end)
 *     and never scroll the page while the list is open (default prevented);
 *   - Enter selects the active option without submitting an enclosing form,
 *     and falls through to the form when the list is closed or nothing is
 *     active (Enter-with-list-open-but-nothing-active closes the list);
 *   - Escape dismisses the list without clearing the typed text;
 *   - Tab closes the list without trapping focus (default NOT prevented);
 *   - hover never overrides the keyboard-driven active option;
 *   - the wiring is announced: role=combobox, aria-expanded, aria-controls,
 *     role=listbox/option, aria-selected, aria-activedescendant.
 *
 * No @testing-library/react in this package — createRoot + act with native
 * DOM events, per the SessionPrimitive.test.tsx pattern. dispatchEvent
 * returns false exactly when preventDefault was called; that return value is
 * the page-scroll / form-submit contract under jsdom.
 */
import { act, useState } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { Autosuggest } from '../design-system'

const OPTIONS = [
  { value: 'project_id', description: 'filter property' },
  { value: 'priority', description: 'filter property' },
  { value: 'progress', description: 'filter property' },
]

function Harness({ options = OPTIONS }: { options?: { value: string; description?: string }[] }) {
  const [value, setValue] = useState('')
  return (
    <Autosuggest
      value={value}
      options={options}
      ariaLabel="Test search"
      onChange={(event: { detail: { value: string } }) => setValue(event.detail.value)}
    />
  )
}

describe('Autosuggest keyboard operation (ENC-TSK-P57)', () => {
  let container: HTMLDivElement
  let root: Root

  beforeAll(() => {
    // jsdom has no scrollIntoView; the component guards the call, but
    // stubbing it lets the keep-active-in-view behaviour be asserted.
    Element.prototype.scrollIntoView = vi.fn()
  })

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    vi.mocked(Element.prototype.scrollIntoView).mockClear()
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  function mount(options?: { value: string; description?: string }[]) {
    act(() => {
      root.render(<Harness options={options} />)
    })
  }

  function input(): HTMLInputElement {
    const el = container.querySelector('input')
    if (!el) throw new Error('input not rendered')
    return el
  }

  function listbox(): HTMLElement | null {
    return container.querySelector('[role="listbox"]')
  }

  function optionEls(): HTMLElement[] {
    return Array.from(container.querySelectorAll('[role="option"]'))
  }

  function type(text: string) {
    const el = input()
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set
    act(() => {
      setter?.call(el, text)
      el.dispatchEvent(new Event('input', { bubbles: true }))
    })
  }

  /** Returns true when default was NOT prevented (page scroll / form submit would proceed). */
  function pressKey(key: string): boolean {
    let notPrevented = true
    act(() => {
      notPrevented = input().dispatchEvent(
        new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true }),
      )
    })
    return notPrevented
  }

  it('typing opens the list; the input is a combobox and the list is announced', () => {
    mount()
    expect(input()).toHaveAttribute('role', 'combobox')
    expect(input()).toHaveAttribute('aria-expanded', 'false')
    expect(input()).toHaveAttribute('aria-autocomplete', 'list')

    type('pr')
    const list = listbox()
    expect(list).not.toBeNull()
    expect(input()).toHaveAttribute('aria-expanded', 'true')
    expect(input()).toHaveAttribute('aria-controls', list?.id)
    expect(list?.id).toBeTruthy()
    expect(optionEls()).toHaveLength(3)
  })

  it('ArrowDown moves the active option, sets aria-activedescendant + aria-selected, and prevents page scroll', () => {
    mount()
    type('pr')

    const notPrevented = pressKey('ArrowDown')
    expect(notPrevented).toBe(false) // preventDefault called — the page must not scroll under the open list

    const options = optionEls()
    expect(options[0]).toHaveClass('ev2-auto__opt--active')
    expect(options[0]).toHaveAttribute('aria-selected', 'true')
    expect(options[1]).toHaveAttribute('aria-selected', 'false')
    expect(input()).toHaveAttribute('aria-activedescendant', options[0].id)
    expect(Element.prototype.scrollIntoView).toHaveBeenCalled()
  })

  it('wraps: ArrowDown past the last option returns to the first; ArrowUp from the first goes to the last', () => {
    mount()
    type('pr')

    pressKey('ArrowDown') // -> 0
    pressKey('ArrowDown') // -> 1
    pressKey('ArrowDown') // -> 2 (last)
    pressKey('ArrowDown') // wrap -> 0
    expect(input()).toHaveAttribute('aria-activedescendant', optionEls()[0].id)

    pressKey('ArrowUp') // wrap -> 2
    expect(input()).toHaveAttribute('aria-activedescendant', optionEls()[2].id)
  })

  it('ArrowUp with the list closed opens it with the LAST option active', () => {
    mount()
    type('pr')
    pressKey('Escape')
    expect(listbox()).toBeNull()

    pressKey('ArrowUp')
    const options = optionEls()
    expect(options.length).toBeGreaterThan(0)
    expect(input()).toHaveAttribute('aria-activedescendant', options[options.length - 1].id)
  })

  it('Enter selects the active option, closes the list, and prevents default (no form submit)', () => {
    mount()
    type('pr')
    pressKey('ArrowDown')
    pressKey('ArrowDown')

    const notPrevented = pressKey('Enter')
    expect(notPrevented).toBe(false) // selection must not become an accidental submit/search
    expect(input()).toHaveValue('priority')
    expect(listbox()).toBeNull()
  })

  it('Enter with the list open but nothing active closes the list and does NOT prevent default (search runs)', () => {
    mount()
    type('pr')
    const notPrevented = pressKey('Enter')
    expect(notPrevented).toBe(true)
    expect(listbox()).toBeNull()
  })

  it('Enter with the list closed does NOT prevent default (search runs)', () => {
    mount()
    const notPrevented = pressKey('Enter')
    expect(notPrevented).toBe(true)
  })

  it('Escape dismisses the list without clearing the typed text; typing reopens it', () => {
    mount()
    type('pr')

    const notPrevented = pressKey('Escape')
    expect(notPrevented).toBe(false)
    expect(listbox()).toBeNull()
    expect(input()).toHaveValue('pr')
    expect(input()).not.toHaveAttribute('aria-activedescendant')

    type('pri')
    expect(listbox()).not.toBeNull()
  })

  it('Tab closes the list and does not prevent default, so focus moves on', () => {
    mount()
    type('pr')
    const notPrevented = pressKey('Tab')
    expect(notPrevented).toBe(true)
    expect(listbox()).toBeNull()
  })

  it('typing resets the active option (stale highlight cannot survive a filter change)', () => {
    mount()
    type('pr')
    pressKey('ArrowDown')
    expect(input().getAttribute('aria-activedescendant')).toContain('-opt-0')

    type('pri')
    expect(input()).not.toHaveAttribute('aria-activedescendant')
  })

  it('arrow keys with no matching options leave the page alone when the list is closed', () => {
    mount([])
    const notPrevented = pressKey('ArrowDown')
    expect(notPrevented).toBe(true)
  })

  it('mouse selection still works and hover does not move the keyboard-active option', () => {
    mount()
    type('pr')
    pressKey('ArrowDown') // keyboard picks option 0

    const options = optionEls()
    act(() => {
      options[2].dispatchEvent(new MouseEvent('mouseover', { bubbles: true }))
      options[2].dispatchEvent(new MouseEvent('mouseenter', { bubbles: false }))
    })
    // incidental mouse movement must not override the keyboard selection
    expect(input()).toHaveAttribute('aria-activedescendant', optionEls()[0].id)

    act(() => {
      options[2].dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }))
    })
    expect(input()).toHaveValue('progress')
    expect(listbox()).toBeNull()
  })
})
