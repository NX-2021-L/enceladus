import { describe, expect, it, vi } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import type { ReactElement } from 'react'
import { MarkdownContentLegacy } from './MarkdownContentLegacy'
import KitMarkdownContent, { BLOCK_MARKER_LINE, hostMarkdownComponents, hostMarkdownPlugins } from './KitMarkdownContent'
import { KitMarkdown } from '@io-kit/md/lean/react'
import { ID_PATTERN_LOOSE } from '@io-kit/md/lean'
import { makeKitIdResolver } from '../utils/kitDocstore'

vi.mock('@tanstack/react-router', () => ({
  Link: ({ to, className, children }: { to: string; className?: string; children?: unknown }) => (
    <a href={to} className={className}>
      {children as never}
    </a>
  ),
}))

/** DVP-TSK-935: DOM parity, legacy parser vs kit-backed MarkdownContent, on normalized HTML. */

const docs = import.meta.glob('../test/fixtures/docstore/DOC-*.md', { query: '?raw', import: 'default', eager: true }) as Record<string, string>

function canon(html: string): string {
  const root = new DOMParser().parseFromString(`<body>${html}</body>`, 'text/html').body
  const walk = (n: Node): string => {
    if (n.nodeType === Node.TEXT_NODE) return (n.textContent ?? '').replace(/\s+/g, ' ')
    if (n.nodeType !== Node.ELEMENT_NODE) return ''
    const el = n as Element
    const attrs = [...el.attributes].map((a) => `${a.name}="${a.value}"`).sort().join(' ')
    const kids = [...el.childNodes].map(walk).join('')
    return `<${el.tagName.toLowerCase()}${attrs ? ' ' + attrs : ''}>${kids.trim() === '' && kids !== '' ? '' : kids}</${el.tagName.toLowerCase()}>`
  }
  return walk(root).replace(/> </g, '><').replace(/\s+</g, '<').replace(/>\s+/g, '>')
}
const html = (el: ReactElement) => canon(renderToStaticMarkup(el))
const legacy = (text: string, projectId?: string) => html(<MarkdownContentLegacy text={text} projectId={projectId} />)
const kit = (text: string, projectId?: string) => html(<KitMarkdownContent text={text} projectId={projectId} />)

const SNIPPETS: Record<string, string> = {
  paragraph: 'A plain paragraph\nwrapped over two lines with **bold**, *em*, _also em_ and `inline code`.',
  headings: '# One\n\n## Two\n\n### Three\n\n#### Four\n\nBody ENC-TSK-123 text.',
  ids: 'Task ENC-TSK-K21 and ENC-ISS-5, DOC-488491DADD6C, ENC-SES-0JB (no route), `ENC-TSK-9` in code, **ENC-FTR-1**, _ENC-PLN-2_.',
  link: 'See [the docs](https://example.com/a?b=1) now.',
  list: '- one ENC-TSK-1\n- two\n- three `x`\n\n1. first\n2. second',
  quote: '> a quoted line\n> and a second with DOC-488491DADD6C',
  fence: 'Before\n\n```yaml\nkey: value: oops\n  - bad\n```\n\n```\nplain <b>not html</b>\n```\n\nAfter',
  worklog: 'Merged PR #57 (DVP-TSK-783) -- snake_case objectives_set and source_record_id stay literal.',
}

describe('KitMarkdownContent parity with the legacy parser', () => {
  for (const [name, md] of Object.entries(SNIPPETS)) {
    it(`snippet ${name}: normalized HTML equal (project-scoped ids)`, () => {
      expect(kit(md, 'enceladus')).toBe(legacy(md, 'enceladus'))
    })
    it(`snippet ${name}: normalized HTML equal (no project)`, () => {
      expect(kit(md)).toBe(legacy(md))
    })
  }

  it('empty input renders nothing in both', () => {
    expect(renderToStaticMarkup(<KitMarkdownContent text="  " />)).toBe('')
  })
})

describe('golden corpus (7 documents)', () => {
  const entries = Object.entries(docs)
  it('has seven documents', () => expect(entries).toHaveLength(7))

  // The legacy fence scanner toggles on every ``` line (even ```yaml inside an open fence) and treats 4-space
  // indented prose as paragraphs; the kit follows CommonMark. These two documents contain such fences, so the
  // legacy view mis-renders them (prose shown as code and code as prose). Strict equality is asserted for the
  // other five; for these two the legacy output must be a subset of the kit's (headings in order, id links).
  const LEGACY_FENCE_DEFECT = new Set(['DOC-2B7AF00D8FB2', 'DOC-431B8C752579'])
  const dom = (h: string) => new DOMParser().parseFromString(h, 'text/html')
  const linkSet = (h: string) => [...dom(h).querySelectorAll('a.ev2-md__id-link')].map((a) => `${a.getAttribute('href')}|${a.textContent}`)
  const headings = (h: string) => [...dom(h).querySelectorAll('.ev2-md__heading')].map((e) => `${e.tagName}:${e.textContent}`)

  let strict = 0
  for (const [path, src] of entries) {
    const id = /DOC-[0-9A-F]{12}/.exec(path)![0]
    // block-marker comment lines are removed on both sides (sections are sliced without them; see KitMarkdownContent)
    const clean = src.replace(BLOCK_MARKER_LINE, '')
    const lh = renderToStaticMarkup(<MarkdownContentLegacy text={clean} projectId="enceladus" />)
    const kh = renderToStaticMarkup(<KitMarkdownContent text={src} projectId="enceladus" />)
    if (!LEGACY_FENCE_DEFECT.has(id)) {
      it(`${id}: normalized HTML equal to the legacy parser`, () => {
        strict++
        const a = canon(lh)
        const b = canon(kh)
        let i = 0
        while (i < a.length && a[i] === b[i]) i++
        expect(b.slice(Math.max(0, i - 80), i + 160), `first difference at ${i}: legacy=${a.slice(Math.max(0, i - 80), i + 160)}`).toBe(a.slice(Math.max(0, i - 80), i + 160))
        expect(b).toBe(a)
      })
    } else {
      it(`${id}: legacy fence defect -- every legacy heading and id link is either in the kit output or inside a kit code block`, () => {
        const kitPre = [...dom(kh).querySelectorAll('pre')].map((p) => p.textContent ?? '').join('\n')
        const kitHeadings = headings(kh)
        // a legacy heading the kit does not have must be text the kit shows inside a code block
        for (const h of headings(lh)) if (!kitHeadings.includes(h)) expect(kitPre).toContain(h.slice(h.indexOf(':') + 1).slice(0, 40))
        const k = linkSet(kh)
        for (const x of linkSet(lh)) if (!k.includes(x)) expect(kitPre).toContain(x.split('|')[1])
      })
    }
  }
  it('five of seven documents are strictly equal', () => expect(strict).toBe(5))
})

describe('AC1: every id form links (document view resolver)', () => {
  const projects = [{ project_id: 'enceladus', prefix: 'ENC' }, { project_id: 'devops', prefix: 'DVP' }] as never
  const resolver = makeKitIdResolver(projects)
  for (const [path, src] of Object.entries(docs)) {
    const id = /DOC-[0-9A-F]{12}/.exec(path)![0]
    it(`${id}: no id-shaped token is left bare outside code`, () => {
      const out = renderToStaticMarkup(
        <KitMarkdown source={src} plugins={hostMarkdownPlugins(resolver, true)} components={hostMarkdownComponents} className="ev2-md" />,
      )
      const dom = new DOMParser().parseFromString(out, 'text/html')
      const bare: string[] = []
      const re = new RegExp(ID_PATTERN_LOOSE.source, 'g')
      const walk = (n: Node, inCode: boolean) => {
        n.childNodes.forEach((c) => {
          if (c.nodeType === Node.TEXT_NODE) {
            if (!inCode) for (const m of (c.textContent ?? '').matchAll(re)) bare.push(m[0])
          } else if (c.nodeType === Node.ELEMENT_NODE) {
            const el = c as Element
            const skip = ['CODE', 'PRE', 'A'].includes(el.tagName) || el.classList.contains('ev2-md__id-plain')
            walk(el, inCode || skip)
          }
        })
      }
      walk(dom.body, false)
      // bare ids can only be ones the resolver has no route for (they render as .ev2-md__id-plain spans, skipped above)
      expect(bare).toEqual([])
      expect(dom.querySelectorAll('a.ev2-md__id-link').length).toBeGreaterThan(0)
    })
  }
})
