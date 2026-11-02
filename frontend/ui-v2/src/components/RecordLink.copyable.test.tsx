import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RecordLink } from './RecordLink'

vi.mock('@tanstack/react-query', () => ({ useQuery: () => ({ data: [] }) }))
vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, className }: { children: unknown; className?: string }) => (
    <a href="/t" className={className}>
      {children as never}
    </a>
  ),
}))
vi.mock('../api/projectRegistry', () => ({ projectRegistryQueryOptions: {} }))
vi.mock('../routes/recordLink', () => ({
  resolveRecordTarget: (id: string) => (id.startsWith('ENC-') ? { to: '/t', params: {} } : null),
}))

/** ENC-TSK-R80-0H / ENC-FTR-151 AC-5 -- `copyable` prop on the shared RecordLink. */
describe('RecordLink copyable', () => {
  let container: HTMLDivElement
  let root: Root
  const writeText = vi.fn().mockResolvedValue(undefined)

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    writeText.mockClear()
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })
  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  it('renders no copy button by default', () => {
    act(() => root.render(<RecordLink id="ENC-TSK-1" />))
    expect(container.querySelector('[aria-label^="Copy"]')).toBeNull()
  })

  it('renders a sibling copy button right of the link that copies the bare id, even with custom children', async () => {
    act(() => root.render(<RecordLink id="ENC-TSK-1" copyable>See task</RecordLink>))
    const link = container.querySelector('a') as HTMLAnchorElement
    const btn = container.querySelector('[aria-label="Copy ENC-TSK-1"]') as HTMLButtonElement
    expect(btn.tagName).toBe('BUTTON')
    expect(link.contains(btn)).toBe(false)
    expect(link.nextElementSibling).toBe(btn)
    await act(async () => {
      btn.click()
    })
    expect(writeText).toHaveBeenCalledWith('ENC-TSK-1')
  })

  it('also copies when the id cannot be resolved to a link (plain span)', () => {
    act(() => root.render(<RecordLink id="NOPE-1" copyable />))
    expect(container.querySelector('a')).toBeNull()
    expect(container.querySelector('[aria-label="Copy NOPE-1"]')).not.toBeNull()
  })
})
