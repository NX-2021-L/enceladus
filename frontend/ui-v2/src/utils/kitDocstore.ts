/**
 * kitDocstore.ts -- DVP-TSK-916: host glue for @io-kit/md's docstore preset.
 *
 *  - makeKitIdResolver: maps ENC-/DVP-/INT-/... record ids and DOC- ids to
 *    ui-v2 routes (the same targets resolveRecordTarget gives the command
 *    palette). Ids with no route resolve to null, so the kit renders them as
 *    plain monospace rather than a dead link.
 *  - kitSections: derives the section outline/editor model from the kit's
 *    parse (block ids + heading paths + ordinals). These are exactly the
 *    fields `elr doc_patch --anchor` and the patchSection API address by.
 */
import { docstore, parse, highlighter, type IdResolver, type MdDocument, type OutlineNode, type MdPlugin } from '@io-kit/md/lean'
import json from 'highlight.js/lib/languages/json'
import yaml from 'highlight.js/lib/languages/yaml'
import typescript from 'highlight.js/lib/languages/typescript'
import python from 'highlight.js/lib/languages/python'
import bash from 'highlight.js/lib/languages/bash'
import sql from 'highlight.js/lib/languages/sql'
import xml from 'highlight.js/lib/languages/xml'
import markdown from 'highlight.js/lib/languages/markdown'
import type { ProjectSummary } from '../api/projects'
import type { DocumentOutlineEntry } from '../api/documentManifest'
import { resolveRecordTarget } from '../routes/recordLink'
import { sectionKey, type DocumentSection } from './documentSections'

const BLOCK_COMMENT_RE = /^<!--\s*enc:block:[A-Za-z0-9_-]+\s*-->\s*$/

export function makeKitIdResolver(projects: ProjectSummary[]): IdResolver {
  return (id) => {
    const target = resolveRecordTarget(id, projects)
    if (!target) return null
    const href = target.to.replace(/\$(\w+)/g, (_m, key: string) => encodeURIComponent(target.params[key] ?? ''))
    return href.includes('$') ? null : { href, title: id }
  }
}

export function kitDocstorePlugins(projects: ProjectSummary[]): MdPlugin[] {
  // lean entry + 8 grammars (DVP-TSK-924): lives in the lazy KitDocumentView chunk, never the initial route.
  const code = highlighter({
    languages: { json, yaml, typescript, python, bash, sql, xml, markdown },
    aliases: { typescript: ['ts', 'tsx'], python: ['py'], bash: ['sh', 'shell'], yaml: ['yml'], xml: ['html'] },
  })
  return docstore({ resolver: makeKitIdResolver(projects), code })
}

export interface KitSectionItem {
  /** Kit heading slug, the `#<slug>` anchor of the rendered heading. */
  slug: string
  /** The model SectionEditor and the "Updated" badges already consume. */
  section: DocumentSection
}

export interface KitSections {
  doc: MdDocument
  items: KitSectionItem[]
}

function flatten(nodes: OutlineNode[]): OutlineNode[] {
  return nodes.flatMap((n) => [n, ...flatten(n.children)])
}

function lineOf(source: string, offset: number): number {
  let line = 1
  for (let i = 0; i < offset && i < source.length; i++) if (source.charCodeAt(i) === 10) line++
  return line
}

/** Parse once and derive one editor section per non-title heading, in document order. */
export function kitSections(source: string): KitSections {
  const doc = parse(source)
  const flat = flatten(doc.outline)
  const items: KitSectionItem[] = []
  flat.forEach((node, i) => {
    if (node.depth === 1 && node.headingPath.length === 0) return // the document title is not a section
    const { start } = node.position
    // a section runs to the next heading of the same or a shallower depth (sub-sections are part of it)
    const next = flat.slice(i + 1).find((n) => n.depth <= node.depth)
    const end = next ? next.position.start : source.length
    const lines = source.slice(start, end).split('\n')
    let from = 1
    if (BLOCK_COMMENT_RE.test((lines[from] ?? '').trim())) from += 1
    const body = lines.slice(from).join('\n').replace(/^\n+/, '').replace(/\n+$/, '')
    const entry: DocumentOutlineEntry = {
      heading_path: node.headingPath,
      level: node.depth,
      ordinal: node.ordinal,
      block_id: node.blockId,
      line_start: lineOf(source, start),
      line_end: lineOf(source, end),
      section_bytes: end - start,
    }
    items.push({
      slug: node.slug,
      section: { entry, key: sectionKey(entry), headingText: node.text, body },
    })
  })
  return { doc, items }
}
