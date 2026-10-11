import { Children, isValidElement, type ComponentType, type ReactElement, type ReactNode } from 'react'
import { Link } from '@tanstack/react-router'
import { KitMarkdown } from '@io-kit/md/lean/react'
import { docstore, ID_PATTERN_LOOSE, type IdResolver, type MdPlugin } from '@io-kit/md/lean'
import { ID_TOKEN_SOURCE, resolveIdHref } from './MarkdownContentLegacy'
import type { MarkdownContentProps } from './markdownContentTypes'
import './markdownContent.css'

/**
 * DVP-TSK-935: MarkdownContent on @io-kit/md. The kit owns parsing, sanitizing and id matching; the
 * host keeps its CURRENT look by supplying the legacy classes and tags through kit component slots,
 * so the DOM equals MarkdownContentLegacy's (asserted by KitMarkdownContent.parity.test.tsx).
 *
 * Intentional, documented differences (the legacy parser is a subset of CommonMark):
 *  - tables, images and hard breaks render as real elements instead of
 *    being flattened into paragraph text (nested lists are flattened like the legacy model; a thematic
 *    break keeps the legacy literal "---" paragraph);
 *  - bare URLs are NOT autolinked (the legacy parser never linked them; the autolink is rendered as text);
 *  - `<!-- enc:block:ID -->` marker lines are removed before rendering (the legacy whole-body fallback
 *    showed them as literal paragraph text; sections are already sliced without them);
 *  - the legacy fence scanner toggled on EVERY ``` line, so a ```yaml line inside an open fence flipped
 *    code and prose; the kit follows CommonMark (a fence closes only on a bare fence);
 *  - fenced code drops the `language-x` class (it had no styling).
 */

/** The legacy linker's pattern (ID_TOKEN_SOURCE), as the kit plugin's matcher. */
export const LEGACY_ID_PATTERN = new RegExp(ID_TOKEN_SOURCE)

export function legacyIdResolver(projectId: string | undefined): IdResolver {
  return (id) => {
    const href = resolveIdHref(id, projectId)
    return href ? { href } : null
  }
}

/** Kit plugins that add no DOM of their own: ids (all forms), plain code, nothing else. */
export function hostMarkdownPlugins(resolver: IdResolver, wide: boolean): MdPlugin[] {
  return docstore({
    resolver,
    idPattern: wide ? ID_PATTERN_LOOSE : LEGACY_ID_PATTERN,
    idInHeadings: true,
    yamlView: 'code',
    metaCard: false,
    claimBadges: false,
    anchors: false,
    longTokens: false,
  })
}

type Props = { className?: string; href?: string; children?: ReactNode }

function textOf(node: ReactNode): string {
  if (node == null || typeof node === 'boolean') return ''
  if (typeof node === 'string' || typeof node === 'number') return String(node)
  if (Array.isArray(node)) return node.map(textOf).join('')
  if (isValidElement(node)) return textOf((node.props as { children?: ReactNode }).children)
  return ''
}

/** Replaces `<p>` children with their content (legacy list items and quotes hold inline runs, not paragraphs). */
function unwrapParagraphs(children: ReactNode): ReactNode {
  const out: ReactNode[] = []
  Children.forEach(children, (c) => {
    if (typeof c === 'string' && !c.trim()) return
    if (isValidElement(c) && c.type === P) {
      if (out.length) out.push(' ')
      out.push(...Children.toArray((c.props as { children?: ReactNode }).children))
    } else out.push(c)
  })
  return out
}

function P({ children }: Props) {
  return <p className="ev2-md__p">{children}</p>
}
const heading =
  (tag: 'h3' | 'h4' | 'h5'): ComponentType<Props> =>
  ({ children }) => {
    const Tag = tag
    return <Tag className="ev2-md__heading">{children}</Tag>
  }

function Pre({ children }: Props) {
  const code = Children.toArray(children).find(isValidElement) as ReactElement<{ children?: ReactNode }> | undefined
  return (
    <pre className="ev2-md__pre">
      <code>{textOf(code?.props.children).replace(/\n$/, '')}</code>
    </pre>
  )
}

function Code({ className, children }: Props) {
  if (className?.includes('kit-id')) return <span className="ev2-md__id-plain">{children}</span>
  return <code className="ev2-md__code">{children}</code>
}

function Anchor({ className, href, children }: Props) {
  if (className?.includes('kit-id') && href) {
    return (
      <Link to={href} className="ev2-md__id-link">
        {children}
      </Link>
    )
  }
  if (!href) return <>{children}</>
  // gfm autolink literal (text == href): the legacy parser left bare URLs as text
  if (textOf(children) === href) return <>{children}</>
  return (
    <a href={href} target="_blank" rel="noreferrer" className="ev2-md__link">
      {children}
    </a>
  )
}

function Li({ children }: Props) {
  return <li>{unwrapParagraphs(children)}</li>
}

/** The legacy list model is flat: an indented sub-bullet was just another item of the same list. */
function flattenItems(children: ReactNode): ReactNode[] {
  const out: ReactNode[] = []
  Children.forEach(children, (c) => {
    if (!isValidElement(c) || c.type !== Li) return
    const parts = Children.toArray((c.props as Props).children)
    const isList = (x: ReactNode) => isValidElement(x) && (x.type === Ul || x.type === Ol)
    out.push(<Li key={out.length}>{parts.filter((x) => !isList(x))}</Li>)
    for (const nested of parts.filter(isList)) {
      out.push(...flattenItems((nested as ReactElement<Props>).props.children))
    }
  })
  return out
}

const listOf = (Tag: 'ul' | 'ol'): ComponentType<Props> =>
  function ListEl({ children }) {
    return <Tag className="ev2-md__list">{flattenItems(children)}</Tag>
  }
const Ul = listOf('ul')
const Ol = listOf('ol')

export const hostMarkdownComponents = {
  h1: heading('h3'),
  h2: heading('h4'),
  h3: heading('h5'),
  h4: heading('h5'),
  h5: heading('h5'),
  h6: heading('h5'),
  p: P,
  pre: Pre,
  code: Code,
  a: Anchor,
  ul: Ul,
  ol: Ol,
  li: Li,
  // the legacy parser rendered a thematic break as the literal paragraph "---"
  hr: () => <p className="ev2-md__p">---</p>,
  blockquote: ({ children }: Props) => <blockquote className="ev2-md__quote">{unwrapParagraphs(children)}</blockquote>,
} as never

export const BLOCK_MARKER_LINE = /^[ \t]*<!--\s*enc:block:[A-Za-z0-9_-]+\s*-->[ \t]*\r?\n?/gm

export default function KitMarkdownContent({ text, content, projectId, className, idResolver }: MarkdownContentProps) {
  const raw = text ?? content
  const source = raw ? raw.replace(BLOCK_MARKER_LINE, '') : raw
  // React Compiler memoizes this per (idResolver, projectId)
  const plugins = hostMarkdownPlugins(idResolver ?? legacyIdResolver(projectId), !!idResolver)
  if (!source || !source.trim()) return null
  return (
    <KitMarkdown
      source={source}
      plugins={plugins}
      components={hostMarkdownComponents}
      className={`ev2-md${className ? ` ${className}` : ''}`}
    />
  )
}
