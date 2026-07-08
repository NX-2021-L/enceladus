import type { ReactNode } from 'react'
import { Link } from '@tanstack/react-router'
import { documentHref, recordHref } from '../routes/recordLink'
import './markdownContent.css'

/**
 * MarkdownContent -- the one shared renderer for every record description,
 * evidence string, worklog entry, and document body in the cockpit
 * (ENC-TSK-M32 / DOC-B6B52E3BB9BB SS5.6-5.7, SS7). Governed text bodies are
 * short-form markdown (headings, emphasis, inline code, lists, links) --
 * never full-doc tables or embeds -- so a small hand-rolled parser keeps the
 * bundle dependency-free and gives full control over the two behaviors no
 * off-the-shelf renderer does out of the box:
 *
 *  - auto-linking inline ENC-*\/DOC-* record IDs to their governed detail
 *    routes (recognized prefixes only -- unrecognized ones render as plain
 *    styled mono text, never a dead link), and
 *  - guaranteeing long unbroken tokens (hashes, URLs) wrap instead of
 *    forcing horizontal scroll on narrow detail pages (ISS-501).
 */

type TrackerType = 'task' | 'issue' | 'feature' | 'plan' | 'lesson'

const TRACKER_PREFIX_TO_TYPE: Record<string, TrackerType> = {
  TSK: 'task',
  ISS: 'issue',
  FTR: 'feature',
  PLN: 'plan',
  LSN: 'lesson',
}

/** Matches every governed ID shape (ENC-<2-5 letter code>-<alnum>, DOC-<hex>)
 *  so every record-ID mention gets the SS2 mono/teal "Record ID" treatment --
 *  not just the five routable tracker types. Only the recognized prefixes
 *  resolve to an actual href (see resolveIdHref); everything else still
 *  renders styled, just unlinked. */
const ID_TOKEN_SOURCE = String.raw`\b(?:ENC-[A-Z]{2,5}-[A-Za-z0-9]+|DOC-[A-Za-z0-9]+)\b`

/** Resolves a governed record-ID token to its detail route, or null when the
 *  prefix isn't one of the five routable tracker types / documents (e.g.
 *  ENC-SES-*, ENC-ESC-*, ENC-AGT-* have no detail route today -- render as
 *  plain mono text rather than a dead link) or, for a tracker prefix,
 *  no projectId was supplied to resolve the project-scoped route against.
 *  Exported as a pure function so it's unit-testable without a
 *  RouterProvider (this package's tests are logic-level, not
 *  component-level -- see primitives/SessionPrimitive.test.tsx). */
export function resolveIdHref(token: string, projectId: string | undefined): string | null {
  if (token.startsWith('DOC-')) return documentHref(token)
  const match = /^ENC-(TSK|ISS|FTR|PLN|LSN)-/.exec(token)
  if (match && projectId) {
    return recordHref(projectId, TRACKER_PREFIX_TO_TYPE[match[1]], token)
  }
  return null
}

/** Splits a plain-text run on ENC-*\/DOC-* tokens, wiring recognized IDs to
 *  their route via router Link. */
function linkifyIds(text: string, projectId: string | undefined, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = []
  const re = new RegExp(ID_TOKEN_SOURCE, 'g')
  let lastIndex = 0
  let key = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text))) {
    if (m.index > lastIndex) nodes.push(text.slice(lastIndex, m.index))
    const token = m[0]
    const href = resolveIdHref(token, projectId)
    nodes.push(
      href ? (
        <Link key={`${keyPrefix}-id-${key++}`} to={href} className="ev2-md__id-link">
          {token}
        </Link>
      ) : (
        <span key={`${keyPrefix}-id-${key++}`} className="ev2-md__id-plain">
          {token}
        </span>
      ),
    )
    lastIndex = m.index + token.length
  }
  if (lastIndex < text.length) nodes.push(text.slice(lastIndex))
  return nodes
}

const INLINE_RE = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[[^\]]+\]\([^)]+\))|(_[^_]+_|\*[^*]+\*)/

/** Inline pass: code spans, bold, links, and italics are pulled out first
 *  (their contents are never re-processed for emphasis or ID-linked); the
 *  remaining plain-text runs are handed to linkifyIds. */
function renderInline(text: string, projectId: string | undefined, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = []
  let rest = text
  let key = 0

  while (rest.length > 0) {
    const m = INLINE_RE.exec(rest)
    if (!m) {
      nodes.push(...linkifyIds(rest, projectId, `${keyPrefix}-${key++}`))
      break
    }
    const idx = m.index
    if (idx > 0) {
      nodes.push(...linkifyIds(rest.slice(0, idx), projectId, `${keyPrefix}-${key++}`))
    }
    if (m[1]) {
      nodes.push(
        <code className="ev2-md__code" key={`${keyPrefix}-${key++}`}>
          {m[1].slice(1, -1)}
        </code>,
      )
    } else if (m[2]) {
      nodes.push(<strong key={`${keyPrefix}-${key++}`}>{m[2].slice(2, -2)}</strong>)
    } else if (m[3]) {
      const linkMatch = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(m[3])
      if (linkMatch) {
        nodes.push(
          <a
            key={`${keyPrefix}-${key++}`}
            href={linkMatch[2]}
            target="_blank"
            rel="noreferrer"
            className="ev2-md__link"
          >
            {linkMatch[1]}
          </a>,
        )
      }
    } else if (m[4]) {
      nodes.push(<em key={`${keyPrefix}-${key++}`}>{m[4].slice(1, -1)}</em>)
    }
    rest = rest.slice(idx + m[0].length)
  }
  return nodes
}

type Block =
  | { type: 'heading'; level: number; text: string }
  | { type: 'paragraph'; text: string }
  | { type: 'code'; text: string }
  | { type: 'quote'; text: string }
  | { type: 'list'; ordered: boolean; items: string[] }

const HEADING_RE = /^(#{1,6})\s+(.*)$/
const FENCE_RE = /^```/
const QUOTE_RE = /^>\s?/
const BULLET_RE = /^\s*[-*]\s+(.*)$/
const ORDERED_RE = /^\s*\d+\.\s+(.*)$/
const BLANK_RE = /^\s*$/

/** Compact block-level parser: fenced code, headings, blockquotes, lists,
 *  and paragraphs (blank-line separated). No tables/embeds -- governance
 *  bodies never use them (docstore itself rejects pipe tables). */
function parseBlocks(source: string): Block[] {
  const lines = source.replace(/\r\n/g, '\n').split('\n')
  const blocks: Block[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]

    if (BLANK_RE.test(line)) {
      i++
      continue
    }

    if (FENCE_RE.test(line)) {
      const codeLines: string[] = []
      i++
      while (i < lines.length && !FENCE_RE.test(lines[i])) {
        codeLines.push(lines[i])
        i++
      }
      i++ // skip closing fence
      blocks.push({ type: 'code', text: codeLines.join('\n') })
      continue
    }

    const heading = HEADING_RE.exec(line)
    if (heading) {
      blocks.push({ type: 'heading', level: heading[1].length, text: heading[2].trim() })
      i++
      continue
    }

    if (QUOTE_RE.test(line)) {
      const quoteLines: string[] = []
      while (i < lines.length && QUOTE_RE.test(lines[i])) {
        quoteLines.push(lines[i].replace(QUOTE_RE, ''))
        i++
      }
      blocks.push({ type: 'quote', text: quoteLines.join(' ') })
      continue
    }

    const bulletMatch = BULLET_RE.exec(line)
    const orderedMatch = ORDERED_RE.exec(line)
    if (bulletMatch || orderedMatch) {
      const ordered = !!orderedMatch
      const itemRe = ordered ? ORDERED_RE : BULLET_RE
      const items: string[] = []
      while (i < lines.length) {
        const m = itemRe.exec(lines[i])
        if (!m) break
        items.push(m[1])
        i++
      }
      blocks.push({ type: 'list', ordered, items })
      continue
    }

    const paraLines: string[] = [line]
    i++
    while (
      i < lines.length &&
      !BLANK_RE.test(lines[i]) &&
      !FENCE_RE.test(lines[i]) &&
      !HEADING_RE.test(lines[i]) &&
      !QUOTE_RE.test(lines[i]) &&
      !BULLET_RE.test(lines[i]) &&
      !ORDERED_RE.test(lines[i])
    ) {
      paraLines.push(lines[i])
      i++
    }
    blocks.push({ type: 'paragraph', text: paraLines.join(' ') })
  }

  return blocks
}

function headingTag(level: number): 'h3' | 'h4' | 'h5' {
  if (level <= 1) return 'h3'
  if (level === 2) return 'h4'
  return 'h5'
}

export function MarkdownContent({
  text,
  projectId,
  className,
}: {
  /** Raw markdown source -- a record description, evidence string, worklog
   *  entry, or document body. Renders nothing for empty/whitespace-only
   *  input. */
  text: string | null | undefined
  /** Owning record's project -- resolves bare ENC-TSK/ISS/FTR/PLN/LSN
   *  tokens found inline to a same-project detail route. DOC-* tokens never
   *  need this (document routes are project-agnostic). */
  projectId?: string
  className?: string
}) {
  if (!text || !text.trim()) return null
  const blocks = parseBlocks(text)

  return (
    <div className={`ev2-md${className ? ` ${className}` : ''}`}>
      {blocks.map((block, i) => {
        const key = `b-${i}`
        switch (block.type) {
          case 'heading': {
            const Tag = headingTag(block.level)
            return (
              <Tag className="ev2-md__heading" key={key}>
                {renderInline(block.text, projectId, key)}
              </Tag>
            )
          }
          case 'code':
            return (
              <pre className="ev2-md__pre" key={key}>
                <code>{block.text}</code>
              </pre>
            )
          case 'quote':
            return (
              <blockquote className="ev2-md__quote" key={key}>
                {renderInline(block.text, projectId, key)}
              </blockquote>
            )
          case 'list': {
            const ListTag = block.ordered ? 'ol' : 'ul'
            return (
              <ListTag className="ev2-md__list" key={key}>
                {block.items.map((item, j) => (
                  <li key={`${key}-${j}`}>{renderInline(item, projectId, `${key}-${j}`)}</li>
                ))}
              </ListTag>
            )
          }
          case 'paragraph':
          default:
            return (
              <p className="ev2-md__p" key={key}>
                {renderInline(block.text, projectId, key)}
              </p>
            )
        }
      })}
    </div>
  )
}
