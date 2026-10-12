import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mapCorpusItem } from '../search/corpusSource'
import { buildHeaderSuggestions, HeaderSearch } from './HeaderSearch'

/** DVP-TSK-995 AC: the header launcher is a 44px magnifier that routes to /feed?q= (and Cmd/Ctrl-K opens it). */
const rows = [
  mapCorpusItem({ record_id: 'ENC-TSK-12', record_type: 'task', project_id: 'enceladus', title: 'Pager fix', source: 'tracker', record_key: 'tracker:enceladus:ENC-TSK-12', version_seq: 1 })!,
]

describe('HeaderSearch (kit SearchLauncher)', () => {
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

  it('suggests from the local corpus index', () => {
    const s = buildHeaderSuggestions('pager', rows, [])
    expect(s).toEqual([expect.objectContaining({ id: 'ENC-TSK-12', title: 'Pager fix', href: '/enceladus/task/ENC-TSK-12' })])
  })

  it('DVP-TSK-B11: rows carry structured record meta (id + type), not an "ID · type" string', () => {
    const [s] = buildHeaderSuggestions('pager', rows, [])
    expect(s).toEqual(expect.objectContaining({ recordId: 'ENC-TSK-12', kind: 'task' }))
    expect(s!.subtitle).toBeUndefined()
  })

  it('DVP-TSK-B11: the launcher sheet maps every row hook to the record-row design system', () => {
    const css = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), 'headerSearch.css'), 'utf8')
    const rule = /\.io-sheet\[data-variant="palette"\] \{([^}]*)\}/.exec(css)![1]!
    for (const [hook, value] of [
      ['--io-launcher-title-font', 'var(--font-body)'],
      ['--io-launcher-title-size', '13.5px'],
      ['--io-launcher-title-weight', 'var(--fw-medium)'],
      ['--io-launcher-meta-font', 'var(--font-mono)'],
      ['--io-launcher-id-accent', '100%'],
      ['--io-launcher-kind-muted', '100%'],
    ]) {
      expect(rule).toContain(`${hook}: ${value};`)
    }
    expect(css).not.toMatch(/\.io-search__(title|id|kind|meta)\s*\{/)
  })

  it('opens from the magnifier and Enter routes to /feed?q=', async () => {
    const onNavigate = vi.fn()
    await act(async () => {
      root.render(<HeaderSearch rows={rows} projects={[]} onNavigate={onNavigate} />)
    })
    const button = container.querySelector('button[aria-label="Search"]') as HTMLButtonElement
    expect(button).toBeTruthy()
    await act(async () => button.click())
    const input = document.querySelector('input') as HTMLInputElement
    expect(input).toBeTruthy()
    await act(async () => {
      const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!
      set.call(input, 'feed engine')
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    await act(async () => {
      input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
    })
    expect(onNavigate).toHaveBeenCalledWith('/feed?q=feed%20engine')
  })
})
