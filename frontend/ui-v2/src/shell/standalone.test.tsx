import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { standaloneMeta } from '@io-kit/shell'

/**
 * DVP-TSK-956 -- @io-kit/shell 0.4.0 standalone adoption on the ds2 frame.
 *
 *  1. Inset contract (CSS + inline styles): every position:fixed/sticky rule
 *     uses --io-safe-<edge> for each edge it touches; env(safe-area-inset-*)
 *     appears nowhere in src (the kit owns it); no display-mode gating; no
 *     100vh frame height.
 *  2. index.html carries the kit's standaloneMeta output (viewport-fit=cover,
 *     no maximum-scale) and .io-no-focus-zoom on <html>.
 *  3. Tap-to-top: the app bar is a ScrollTopZone bound to the ds2 inner
 *     scroller, and re-tapping the active nav item scrolls it to the top.
 */

const here = dirname(fileURLToPath(import.meta.url))
const srcRoot = resolve(here, '..')
const uiRoot = resolve(srcRoot, '..')

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) {
      if (name === 'fixtures') continue
      walk(full, out)
    } else out.push(full)
  }
  return out
}
const files = walk(srcRoot).filter((f) => !/\.test\.[tj]sx?$/.test(f))
const cssFiles = files.filter((f) => f.endsWith('.css'))
const tsxFiles = files.filter((f) => /\.tsx?$/.test(f))

type Rule = { selector: string; body: string; file: string; raw: string }
function rules(css: string, file: string): Rule[] {
  const out: Rule[] = []
  const re = /([^{}]+)\{([^{}]*)\}/g
  let m: RegExpExecArray | null
  while ((m = re.exec(css))) {
    out.push({ selector: m[1].replace(/\/\*[\s\S]*?\*\//g, '').trim(), body: m[2], file, raw: m[0] })
  }
  return out
}
const EDGES = ['top', 'right', 'bottom', 'left'] as const
function touchedEdges(decls: string): string[] {
  const d = decls.replace(/\/\*[\s\S]*?\*\//g, '')
  if (/(^|[;\s])inset\s*:/.test(d)) return [...EDGES]
  return EDGES.filter((e) => new RegExp(`(^|[;\\s])${e}\\s*:`).test(d))
}
function usesInset(text: string, edge: string): boolean {
  return text.includes(`--io-safe-${edge}`)
}
/** `io-inset-exempt left right: reason` in a comment inside the rule. */
function exemptions(raw: string): string[] {
  const m = /io-inset-exempt\s+([a-z\s]+):/.exec(raw)
  return m ? m[1].trim().split(/\s+/) : []
}

describe('inset contract', () => {
  it('every fixed/sticky CSS rule uses the inset variable of each edge it touches', () => {
    const offenders: string[] = []
    let seen = 0
    for (const file of cssFiles) {
      const css = readFileSync(file, 'utf8')
      for (const r of rules(css, file)) {
        const body = r.body.replace(/\/\*[\s\S]*?\*\//g, '')
        if (!/position\s*:\s*(fixed|sticky)/.test(body)) continue
        // A sticky element that only sets `top` inside a scroller is not against a device edge.
        const sticky = /position\s*:\s*sticky/.test(body)
        if (sticky && !/(^|[;\s])(bottom|inset)\s*:/.test(body)) continue
        seen++
        const exempt = exemptions(r.raw)
        for (const edge of touchedEdges(body)) {
          if (exempt.includes(edge)) continue
          if (!usesInset(body, edge)) offenders.push(`${file.replace(srcRoot, 'src')} ${r.selector} -> ${edge}`)
        }
      }
    }
    expect(seen).toBeGreaterThanOrEqual(3) // drawer, scrim, record action bar
    expect(offenders).toEqual([])
  })

  it('fixed inline-style overlays in TSX use the inset variables', () => {
    const offenders: string[] = []
    for (const file of tsxFiles) {
      const src = readFileSync(file, 'utf8')
      const re = /\{\s*([^{}]*position:\s*'fixed'[^{}]*)\}/g
      let m: RegExpExecArray | null
      while ((m = re.exec(src))) {
        const edges = touchedEdges(m[1].replace(/'/g, '').replace(/,/g, ';'))
        for (const edge of edges) {
          if (!usesInset(m[1], edge)) offenders.push(`${file.replace(srcRoot, 'src')} ${edge}`)
        }
      }
    }
    expect(offenders).toEqual([])
  })

  it('src never reads env(safe-area-inset-*) itself, gates on display-mode, or sizes the frame with 100vh', () => {
    for (const file of [...cssFiles, ...tsxFiles]) {
      const text = readFileSync(file, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
      const rel = file.replace(srcRoot, 'src')
      expect(text, `${rel} env(safe-area-inset)`).not.toMatch(/env\(\s*safe-area-inset/)
      expect(text, `${rel} display-mode`).not.toMatch(/display-mode|navigator\.standalone/)
      if (rel === 'src/shell/shell.css') expect(text).not.toMatch(/min-height:\s*100vh/)
    }
  })

  it('the shell frame is dvh and the top inset has exactly one consumer (the app bar wrapper)', () => {
    const shell = readFileSync(join(srcRoot, 'shell/shell.css'), 'utf8')
    expect(shell).toMatch(/min-height:\s*100dvh/)
    const topConsumers = files
      .filter((f) => /\.(css|tsx?)$/.test(f))
      .filter((f) => /--io-safe-top|io-safe-top/.test(readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')))
    // AppShell (the wrapper), shell.css (drawer/scrim offsets below the bar), and the full-screen overlays.
    expect(topConsumers.map((f) => f.replace(srcRoot, 'src')).sort()).toEqual(
      [
        'src/auth/AuthGate.tsx',
        'src/auth/LoggedOutScreen.tsx',
        'src/shell/AppShell.tsx',
        'src/shell/CommandPalette.tsx',
        'src/shell/shell.css',
      ].sort(),
    )
  })

  it('main.tsx imports the kit css', () => {
    expect(readFileSync(join(srcRoot, 'main.tsx'), 'utf8')).toContain("import '@io-kit/shell/io-kit.css'")
  })
})

describe('index.html', () => {
  const html = readFileSync(join(uiRoot, 'index.html'), 'utf8')
  const kit = standaloneMeta({ title: 'Enceladus', themeColor: '#0A0A0F' })

  it('carries the standaloneMeta viewport and apple meta', () => {
    expect(html).toContain(`<meta name="viewport" content="${kit.viewport}" />`)
    for (const { name, content } of kit.meta) {
      expect(html).toContain(`<meta name="${name}" content="${content}" />`)
    }
  })

  it('keeps pinch zoom and cover, and marks the root no-focus-zoom', () => {
    expect(html).toContain('viewport-fit=cover')
    expect(html.replace(/<!--[\s\S]*?-->/g, '')).not.toMatch(/maximum-scale|user-scalable/)
    expect(html).toMatch(/<html[^>]*class="[^"]*io-no-focus-zoom/)
  })
})

describe('tap-to-top', () => {
  const activePath = '/projects'
  const navigateMock = vi.fn()
  let host: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    vi.resetModules()
    navigateMock.mockReset()
    window.matchMedia = vi.fn().mockImplementation((q: string) => ({
      matches: true,
      media: q,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    })) as unknown as typeof window.matchMedia
    vi.doMock('@tanstack/react-router', () => ({
      useNavigate: () => navigateMock,
      useRouterState: ({ select }: { select: (s: unknown) => unknown }) =>
        select({ location: { pathname: activePath } }),
    }))
    vi.doMock('../components/OfflineLayer', () => ({
      ConflictMergeModal: () => null,
      MutationErrorFlashbar: () => null,
      OfflinePendingFlashbar: () => null,
    }))
    vi.doMock('./useCommandNavigation', () => ({ useCommandNavigation: () => ({ submit: vi.fn() }) }))
    vi.doMock('./CommandPalette', () => ({ CommandPalette: () => null }))
    vi.doMock('../auth/logout', () => ({ performLogout: vi.fn() }))
    vi.doMock('../offline/swUpdate', () => ({ refreshApp: vi.fn() }))
    host = document.createElement('div')
    document.body.appendChild(host)
  })
  afterEach(() => {
    act(() => root?.unmount())
    host.remove()
    vi.doUnmock('@tanstack/react-router')
  })

  const click = (el: Element) => act(() => (el as HTMLElement).click())
  const link = (text: string) =>
    [...host.querySelectorAll('a')].find((a) => a.textContent?.trim() === text)!

  async function mount() {
    const { AppShell } = await import('./AppShell')
    root = createRoot(host)
    act(() => root.render(<AppShell><p>page</p></AppShell>))
    const scroller = host.querySelector<HTMLElement>('.ev2-al__content')!
    const scrollTo = vi.fn()
    scroller.scrollTo = scrollTo as unknown as typeof scroller.scrollTo
    return { scroller, scrollTo }
  }

  it('marks the ds2 inner scroller and wraps the app bar in a ScrollTopZone with the top inset', async () => {
    const { scroller } = await mount()
    expect(scroller).toHaveAttribute('data-io-scroller')
    const zone = host.querySelector('[data-io-scroll-top-zone]')!
    expect(zone).toHaveClass('io-safe-top')
    expect(zone.querySelector('header.ev2-tn')).not.toBeNull()
  })

  it('tapping the non-interactive bar scrolls the scroller to the top; controls do not', async () => {
    const { scrollTo } = await mount()
    click(host.querySelector('header.ev2-tn')!)
    expect(scrollTo).toHaveBeenCalledTimes(1)
    expect(scrollTo.mock.calls[0][0]).toMatchObject({ top: 0 })
    scrollTo.mockClear()
    click(host.querySelector('.ev2-tn__btn')!)
    click(host.querySelector('.ev2-tn__search-input')!)
    click(host.querySelector('a.ev2-tn__brand')!)
    expect(scrollTo).not.toHaveBeenCalled()
  })

  it('tapping the safe-area strip (the zone itself) scrolls to the top', async () => {
    const { scrollTo } = await mount()
    click(host.querySelector('[data-io-scroll-top-zone]')!)
    expect(scrollTo).toHaveBeenCalledTimes(1)
  })

  it('re-tapping the active nav item scrolls to top; another item does not', async () => {
    const { useUiStore } = await import('../store/uiStore')
    const { scrollTo } = await mount()
    act(() => useUiStore.getState().setSidebarOpen(true))
    click(link('Feed'))
    expect(scrollTo).not.toHaveBeenCalled()
    expect(navigateMock).toHaveBeenCalledWith({ to: '/feed' })
    click(link('Projects'))
    expect(scrollTo).toHaveBeenCalledTimes(1)
  })

  it('Escape still closes the nav drawer', async () => {
    const { useUiStore } = await import('../store/uiStore')
    await mount()
    act(() => useUiStore.getState().setSidebarOpen(true))
    expect(useUiStore.getState().sidebarOpen).toBe(true)
    act(() => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    })
    expect(useUiStore.getState().sidebarOpen).toBe(false)
  })
})
