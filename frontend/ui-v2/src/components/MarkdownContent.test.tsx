import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { MarkdownContent, resolveIdHref } from './MarkdownContent'

/**
 * ENC-TSK-M32. No @testing-library/react in this package — react-dom/client
 * createRoot + act, matching the established convention (see
 * primitives/SessionPrimitive.test.tsx).
 *
 * Href resolution is covered as a pure-function unit test (resolveIdHref)
 * rather than by rendering a resolved <Link> in the DOM tests below: the
 * router's Link requires a live RouterProvider context tree (no test in
 * this package builds one — everything here is logic-level), so DOM
 * rendering tests below only ever feed text whose IDs are either absent or
 * intentionally unresolved (no projectId / unrecognized prefix), which
 * fall through to a plain <span>, not <Link>.
 */

describe('MarkdownContent', () => {
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

  it('renders nothing for empty/whitespace/null input', () => {
    act(() => {
      root.render(<MarkdownContent text="   " />)
    })
    expect(container.innerHTML).toBe('')

    act(() => {
      root.render(<MarkdownContent text={null} />)
    })
    expect(container.innerHTML).toBe('')
  })

  it('parses headings, bold, italic, and inline code — no raw ## or ** in output', () => {
    act(() => {
      root.render(
        <MarkdownContent text={'## Heading\n\nThis is **bold** and *italic* and `code`.'} />,
      )
    })
    expect(container.querySelector('h4')?.textContent).toBe('Heading')
    expect(container.querySelector('strong')?.textContent).toBe('bold')
    expect(container.querySelector('em')?.textContent).toBe('italic')
    expect(container.querySelector('code')?.textContent).toBe('code')
    expect(container.textContent).not.toContain('##')
    expect(container.textContent).not.toContain('**')
  })

  it('parses unordered and ordered lists', () => {
    act(() => {
      root.render(<MarkdownContent text={'- one\n- two\n- three'} />)
    })
    expect(container.querySelectorAll('ul li').length).toBe(3)

    act(() => {
      root.render(<MarkdownContent text={'1. first\n2. second'} />)
    })
    expect(container.querySelectorAll('ol li').length).toBe(2)
  })

  it('resolves recognized ENC-* tracker IDs to their project-scoped detail route', () => {
    expect(resolveIdHref('ENC-TSK-M32', 'enceladus')).toBe('/enceladus/task/ENC-TSK-M32')
    expect(resolveIdHref('ENC-ISS-501', 'enceladus')).toBe('/enceladus/issue/ENC-ISS-501')
    expect(resolveIdHref('ENC-FTR-096', 'enceladus')).toBe('/enceladus/feature/ENC-FTR-096')
    expect(resolveIdHref('ENC-PLN-006', 'enceladus')).toBe('/enceladus/plan/ENC-PLN-006')
    expect(resolveIdHref('ENC-LSN-011', 'enceladus')).toBe('/enceladus/lesson/ENC-LSN-011')
  })

  it('resolves DOC-* IDs without needing a projectId', () => {
    expect(resolveIdHref('DOC-B6B52E3BB9BB', undefined)).toBe('/document/DOC-B6B52E3BB9BB')
  })

  it('returns null (unlinked) for an unrecognized ENC-* prefix, never a dead link', () => {
    expect(resolveIdHref('ENC-SES-066', 'enceladus')).toBeNull()
    expect(resolveIdHref('ENC-AGT-005', 'enceladus')).toBeNull()
    expect(resolveIdHref('ENC-ESC-004', 'enceladus')).toBeNull()
  })

  it('returns null for a recognized tracker prefix when no projectId is supplied', () => {
    expect(resolveIdHref('ENC-ISS-501', undefined)).toBeNull()
  })

  it('renders an unrecognized ENC-* prefix as plain styled mono text (no router needed, since it never becomes a Link)', () => {
    act(() => {
      root.render(<MarkdownContent text="Session ENC-SES-066 kicked this off." projectId="enceladus" />)
    })
    expect(container.querySelector('a.ev2-md__id-link')).toBeNull()
    const plain = container.querySelector('span.ev2-md__id-plain')
    expect(plain?.textContent).toBe('ENC-SES-066')
  })

  it('renders a tracker ID as plain mono text (not a link) when no projectId is supplied', () => {
    act(() => {
      root.render(<MarkdownContent text="See ENC-ISS-501." />)
    })
    expect(container.querySelector('a.ev2-md__id-link')).toBeNull()
    expect(container.querySelector('span.ev2-md__id-plain')?.textContent).toBe('ENC-ISS-501')
  })

  it('applies overflow-wrap CSS hooks so long unbroken tokens cannot force horizontal scroll', () => {
    const longToken = 'a'.repeat(120)
    act(() => {
      root.render(<MarkdownContent text={`Hash: ${longToken}`} />)
    })
    const root_ = container.querySelector('.ev2-md')
    expect(root_).not.toBeNull()
    expect(container.textContent).toContain(longToken)
  })
})
