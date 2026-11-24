import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { NAV_ITEMS } from './navRegistry'

/**
 * ENC-TSK-S98-0C (ENC-PLN-108 W3.3), DOC-5E1E205FA664 section 5.9 and criterion 1.
 *
 * "Plans appears between Projects and Feed and opens /plans without a full reload, and one list defines the menu."
 *
 * SIDEBAR_ITEMS in AppShell.tsx is what actually renders the drawer, and NAV_ITEMS in navRegistry.ts is the
 * registry section 5.9 says must receive the same entry or be deleted. Deleting it would drop the caps and
 * permission wiring it feeds, so this pins the two in step instead — which is the half of "one list" that can be
 * had without a larger refactor.
 */

const srcRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const read = (rel: string) => readFileSync(resolve(srcRoot, rel), 'utf8')

/** Ordered hrefs of the primary links, read from the array AppShell actually renders. */
function sidebarHrefs(): string[] {
  const src = read('shell/AppShell.tsx')
  const start = src.indexOf('const SIDEBAR_ITEMS = [')
  expect(start, 'SIDEBAR_ITEMS not found in AppShell.tsx').toBeGreaterThan(-1)
  const end = src.indexOf('\n]', start)
  const block = src.slice(start, end)
  return [...block.matchAll(/href:\s*'([^']+)'/g)].map((m) => m[1] as string)
}

describe('Plans menu entry and route (ENC-TSK-S98-0C)', () => {
  it('Plans sits between Projects and Feed in the rendered drawer (R1)', () => {
    const hrefs = sidebarHrefs()
    const projects = hrefs.indexOf('/projects')
    const plans = hrefs.indexOf('/plans')
    const feed = hrefs.indexOf('/feed')
    expect(projects).toBeGreaterThan(-1)
    expect(plans).toBeGreaterThan(-1)
    expect(feed).toBeGreaterThan(-1)
    expect(plans).toBe(projects + 1)
    expect(feed).toBe(plans + 1)
  })

  it('the nav registry carries the same entry, in the same place', () => {
    const ids = NAV_ITEMS.map((i) => (i as { id?: string }).id)
    const plans = ids.indexOf('plans')
    expect(plans).toBe(ids.indexOf('projects') + 1)
    expect(ids.indexOf('feed')).toBe(plans + 1)
    const entry = NAV_ITEMS.find((i) => (i as { id?: string }).id === 'plans') as { route?: string; label?: string }
    expect(entry.route).toBe('/plans')
    expect(entry.label).toBe('Plans')
  })

  it('the drawer link and the registry entry point at the same route', () => {
    const entry = NAV_ITEMS.find((i) => (i as { id?: string }).id === 'plans') as { route?: string }
    expect(sidebarHrefs()).toContain(entry.route)
  })

  it('/plans is a lazy route that validates ?project=, so a filtered view is a shareable URL', () => {
    const router = read('routes/router.tsx')
    const start = router.indexOf('const plansRoute = createRoute({')
    expect(start, '/plans route not declared').toBeGreaterThan(-1)
    const block = router.slice(start, router.indexOf('\n})', start))
    expect(block).toMatch(/path:\s*'\/plans'/)
    expect(block).toMatch(/validateSearch/)
    expect(block).toMatch(/raw\.project/)
    // Lazy, like every other page route: opening Plans must not grow the initial bundle.
    expect(block).toMatch(/lazyRouteComponent\(\(\) => import\('\.\/PlansRoute'\), 'PlansRoute'\)/)
    // Registered, or the link would 404.
    expect(router).toMatch(/addChildren\(\[[\s\S]*\bplansRoute\b[\s\S]*\]\)/)
  })
})
