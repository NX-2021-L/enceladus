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
