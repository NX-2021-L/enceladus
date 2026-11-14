import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// Narrow-viewport feed cards are router <Link>s; a plain anchor is enough to prove no navigation.
vi.mock('@tanstack/react-router', () => ({
  Link: ({ to, children, onClick, className }: { to: string; children: unknown; onClick?: () => void; className?: string }) => (
    <a href={to} className={className} onClick={onClick}>
      {children as never}
    </a>
  ),
}))
import { RecordCard } from './RecordCard'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { Badge } from './Badge'

const copyCss = readFileSync(resolve(process.cwd(), 'src/components/copyIdButton.css'), 'utf8')

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
    expect(container.textContent).toContain('in progress')
    expect(container.textContent).toContain('P0')
    expect(container.textContent).toContain('CHECKED OUT')

    const titleEl = container.querySelector('.ev2-rc__feed-title')
    expect(titleEl).not.toBeNull()
  })

  it('draws the rail from record type, not priority (closed P0 task: done pill, task rail)', () => {
    act(() => {
      root.render(<RecordCard recordId="ENC-TSK-Q91" recordType="task" title="closed P0" status="closed" priority="P0" variant="feed" />)
    })
    const card = container.querySelector('.ev2-rc--feed') as HTMLElement
    expect(card.getAttribute('data-type')).toBe('task')
    expect(card.hasAttribute('data-rail')).toBe(false)
    expect(card.style.borderLeftColor).toBe('')
    expect(container.querySelector('.enc-pill')?.getAttribute('data-role')).toBe('done')
  })

  it('lets a waiting, caution or failed role take the rail (task in pr)', () => {
    act(() => {
      root.render(<RecordCard recordId="ENC-TSK-S59-0B" recordType="task" title="in review" status="pr" variant="feed" />)
    })
    const card = container.querySelector('.ev2-rc--feed') as HTMLElement
    expect(card.getAttribute('data-rail')).toBe('waiting')
    expect(container.querySelector('.enc-pill')?.getAttribute('data-role')).toBe('waiting')
  })

  it('reads underscore task statuses from the feed (merged_main is active)', () => {
    act(() => {
      root.render(<RecordCard recordId="ENC-TSK-X1" recordType="task" title="t" status="merged_main" variant="feed" />)
    })
    expect(container.querySelector('.enc-pill')?.getAttribute('data-role')).toBe('active')
    expect(container.textContent).toContain('merged main')
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

  // ENC-TSK-R80-0H / ENC-FTR-151 AC-1, AC-2, AC-6 -- copy button on every Feed card.
  describe('copy-ID button', () => {
    const writeText = vi.fn().mockResolvedValue(undefined)

    beforeEach(() => {
      vi.useFakeTimers()
      writeText.mockClear()
      Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    })
    afterEach(() => {
      vi.useRealTimers()
    })

    const flush = async () => {
      await act(async () => {
        await Promise.resolve()
      })
    }

    it('renders a labelled copy button immediately right of the ID, 32px hit area, no wrap', () => {
      act(() => {
        root.render(<RecordCard recordId="ENC-FTR-150" title="t" status="open" variant="feed" projectLabel="enceladus" />)
      })
      const ids = container.querySelector('.ev2-rc__feed-ids') as HTMLElement
      const idEl = ids.querySelector('.enc-record-id') as HTMLElement
      const btn = ids.querySelector('[aria-label="Copy ENC-FTR-150"]') as HTMLElement
      expect(btn).not.toBeNull()
      expect(btn.getAttribute('role')).toBe('button')
      expect(btn.tabIndex).toBe(0)
      expect(idEl.nextElementSibling).toBe(btn)
      // AC-6: >= 32px hit area, held on the ID's line without growing the row (negative margins), never wraps.
      expect(copyCss).toMatch(/\.ev2-copy\s*\{[^}]*min-width:\s*32px/)
      expect(copyCss).toMatch(/\.ev2-copy\s*\{[^}]*min-height:\s*32px/)
      expect(copyCss).toMatch(/\.ev2-copy\s*\{[^}]*flex:\s*none/)
      expect(copyCss).toMatch(/\.ev2-copy\s*\{[^}]*margin:\s*-\d+px/)
      // The "Copied" confirmation floats (absolute) so it cannot shift layout.
      expect(copyCss).toMatch(/\.ev2-copy__tip\s*\{[^}]*position:\s*absolute/)
    })

    it('copies the bare ID without selecting the card, then confirms for ~1.5s', async () => {
      const onSelect = vi.fn()
      act(() => {
        root.render(<RecordCard recordId="ENC-FTR-150" title="t" status="open" variant="feed" onSelect={onSelect} />)
      })
      const btn = container.querySelector('[aria-label="Copy ENC-FTR-150"]') as HTMLElement
      act(() => {
        btn.click()
      })
      await flush()
      expect(writeText).toHaveBeenCalledWith('ENC-FTR-150')
      expect(onSelect).not.toHaveBeenCalled()
      expect(container.textContent).toContain('Copied')
      act(() => {
        vi.advanceTimersByTime(1400)
      })
      expect(container.textContent).toContain('Copied')
      act(() => {
        vi.advanceTimersByTime(200)
      })
      expect(container.textContent).not.toContain('Copied')
    })

    it('does not navigate when the card is a link, and works from the keyboard', async () => {
      const onSelect = vi.fn()
      act(() => {
        root.render(
          <RecordCard recordId="ENC-TSK-R80-0H" title="t" status="open" variant="feed" href="/x" onSelect={onSelect} />,
        )
      })
      const btn = container.querySelector('[aria-label="Copy ENC-TSK-R80-0H"]') as HTMLElement
      const click = new MouseEvent('click', { bubbles: true, cancelable: true })
      act(() => {
        btn.dispatchEvent(click)
      })
      await flush()
      expect(click.defaultPrevented).toBe(true)
      expect(onSelect).not.toHaveBeenCalled()
      expect(writeText).toHaveBeenCalledWith('ENC-TSK-R80-0H')

      writeText.mockClear()
      const key = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true })
      act(() => {
        btn.dispatchEvent(key)
      })
      await flush()
      expect(key.defaultPrevented).toBe(true)
      expect(writeText).toHaveBeenCalledWith('ENC-TSK-R80-0H')
    })
  })
})
