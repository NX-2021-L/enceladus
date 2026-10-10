import { createHash } from 'node:crypto'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { parse, replaceSection, sectionAt } from '@io-kit/md'
import { KitMarkdown } from '@io-kit/md/react'
import type { ProjectSummary } from '../api/projects'
import { kitDocstorePlugins, kitSections, makeKitIdResolver } from './kitDocstore'
import { sliceDocumentSections } from './documentSections'

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'test', 'fixtures', 'docstore')
const read = (name: string) => readFileSync(join(dir, name), 'utf8')
const ids = readdirSync(dir)
  .filter((f) => /^DOC-[0-9A-F]{12}\.md$/.test(f))
  .map((f) => f.slice(0, -3))
  .sort()

const projects = [
  { project_id: 'enceladus', prefix: 'ENC' },
  { project_id: 'devops', prefix: 'DVP' },
  { project_id: 'intelligence', prefix: 'INT' },
] as ProjectSummary[]

interface Row {
  heading_path: string[]
  level: number
  ordinal: number
  block_id: string | null
}
const elr = (id: string) => JSON.parse(read(`${id}.outline.json`)) as Row[]
const digestHash = (id: string) => (JSON.parse(read(`${id}.digest.json`)) as { content_hash: string }).content_hash
const render = (src: string) =>
  renderToStaticMarkup(createElement(KitMarkdown, { source: src, plugins: kitDocstorePlugins(projects) }))
const count = (s: string, re: RegExp) => (s.match(re) ?? []).length

describe('host id resolver', () => {
  const resolve = makeKitIdResolver(projects)
  it('maps ENC-/DVP-/INT- tracker ids and DOC- ids to ui-v2 routes', () => {
    expect(resolve('ENC-TSK-K21')?.href).toBe('/enceladus/task/ENC-TSK-K21')
    expect(resolve('DVP-PLN-011')?.href).toBe('/devops/plan/DVP-PLN-011')
    expect(resolve('INT-FTR-7')?.href).toBe('/intelligence/feature/INT-FTR-7')
    expect(resolve('DOC-488491DADD6C')?.href).toBe('/document/DOC-488491DADD6C')
    expect(resolve('ENC-SES-0JB')?.href).toBe('/session/ENC-SES-0JB')
  })
  it('returns null (monospace, never a dead link) for ids with no route', () => {
    expect(resolve('FIN-ABC-777')).toBeNull()
    expect(resolve('ZZZ-TSK-1')).toBeNull()
  })
})

describe('golden corpus: six+ real governed docs incl. the 80 KB BRD (AC1)', () => {
  it('has at least six docs and the BRD edge', () => {
    expect(ids.length).toBeGreaterThanOrEqual(6)
    expect(Buffer.byteLength(read('DOC-4B28ED908326.md')) / 1024).toBeGreaterThan(79)
  })
  for (const id of ids) {
    it(`${id}: renders header card, ids, anchors; snapshot of the rendered structure`, async () => {
      const src = read(`${id}.md`)
      const html = render(src)
      const anchors = [...html.matchAll(/ id="([^"]+)"/g)].map((m) => m[1]!)
      expect(new Set(anchors).size).toBe(anchors.length)
      expect(anchors.every((a) => a.startsWith('user-content-'))).toBe(true)
      expect(html).not.toContain('enc:block')
      expect(html).not.toMatch(/<script|href="javascript:/i)
      const summary = {
        bytes: Buffer.byteLength(html),
        sha256: createHash('sha256').update(html).digest('hex'),
        metaCard: count(html, /class="kit-meta"/g),
        yamlTrees: count(html, /kit-yaml--tree/g),
        idLinks: count(html, /<a class="kit-id" href="\//g),
        unresolvedIds: count(html, /kit-id--unresolved/g),
        claimBadges: count(html, /kit-claim/g),
        anchors: anchors.length,
      }
      expect(summary.idLinks).toBeGreaterThan(0)
      expect(html).toContain('class="kit-id" href="/')
      await expect(JSON.stringify(summary, null, 1)).toMatchFileSnapshot(join(dir, `${id}.golden.json`))
    })
  }
  it('id links point at ui-v2 routes, and claim badges / YAML tree / header card render', () => {
    const html = render(read('DOC-431B8C752579.md'))
    expect(html).toContain('class="kit-meta"')
    expect(html).toContain('kit-yaml--tree')
    expect(html).toMatch(/<a class="kit-id" href="\/devops\/task\/DVP-TSK-781"/)
    expect(html).toMatch(/href="\/document\/DOC-[0-9A-F]{12}"/)
    expect(html).not.toContain('href="/records/')
  })
  it('parses the 80 KB BRD inside a generous budget', () => {
    const src = read('DOC-4B28ED908326.md')
    const t0 = performance.now()
    parse(src)
    expect(performance.now() - t0).toBeLessThan(2000)
  })
})

describe('section outline/editor addressing equals ELR (AC2)', () => {
  for (const id of ids) {
    it(`${id}: kit sections carry the ELR heading_path, level, ordinal and block_id`, () => {
      const src = read(`${id}.md`)
      const { items } = kitSections(src)
      const want = elr(id)
        .filter((r) => !(r.level === 1 && r.heading_path.length === 0)) // title row is not a section
        .map((r) => ({ heading_path: r.heading_path, level: r.level, ordinal: r.ordinal, block_id: r.block_id }))
      expect(items.map((i) => i.section.entry).map((e) => ({
        heading_path: e.heading_path,
        level: e.level,
        ordinal: e.ordinal,
        block_id: e.block_id,
      }))).toEqual(want)
      // Every body is a verbatim slice of the source (the kit, like ELR, is fence-aware even for an unterminated fence).
      for (const { section } of items) expect(src).toContain(section.body)
      // Where the legacy slicer's line-based heading pairing lines up (no '#' lines inside code fences), it agrees
      // with the kit exactly; where it does not, the kit result is the correct one (it parses fences).
      const headingLines = src.split('\n').filter((l) => /^#{1,6}\s+\S/.test(l)).length
      if (headingLines === items.length + 1) {
        const legacy = sliceDocumentSections(src, items.map((i) => i.section.entry))
        expect(items.map((i) => i.section.body)).toEqual(legacy.map((s) => s.body))
      }
    })
  }

  for (const id of ['DOC-431B8C752579', 'DOC-4B28ED908326']) {
    it(`${id}: a doc_patch round trip keeps the same section addressing`, () => {
      const src = read(`${id}.md`)
      const before = kitSections(src).items.map((i) => i.section.entry)
      const target = before.find((e, i) => e.block_id && e.level === 2 && !(before[i + 1] && before[i + 1]!.level > 2))!
      expect(target).toBeDefined()
      // SectionEditor addresses by block_id, else {heading_path, ordinal}; ELR by "H2 / H3".
      const anchor = target.heading_path.join(' / ')
      const section = sectionAt(parse(src), anchor)!
      expect(section.blockId).toBe(target.block_id)
      const res = replaceSection(src, target.heading_path, 'Edited body.\n\n- one\n- two', section.hash)
      expect(res.ok).toBe(true)
      if (!res.ok) return
      const after = kitSections(res.source).items.map((i) => i.section.entry)
      const key = (e: (typeof before)[number]) => [e.heading_path, e.level, e.ordinal, e.block_id]
      expect(after.map(key)).toEqual(before.map(key))
      expect(kitSections(res.source).items.find((i) => i.section.entry.block_id === target.block_id)!.section.body).toContain(
        'Edited body.',
      )
      expect(digestHash(id)).toMatch(/^[0-9a-f]{64}$/)
    })
  }

  it('a stale base hash yields the {theirs, base} conflict the existing conflict view consumes', () => {
    const src = read('DOC-431B8C752579.md')
    const { items } = kitSections(src)
    const entry = items.find((i) => i.section.entry.level === 2)!.section.entry
    const res = replaceSection(src, entry.heading_path, 'x', 'deadbeef')
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.conflict.base).toBe('deadbeef')
  })
})
