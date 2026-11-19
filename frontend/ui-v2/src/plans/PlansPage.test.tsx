import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { PlansPage } from './PlansPage'
import { buildDemoCorpus, DEMO_NOW, demoPlan } from './__fixtures__/demoCorpus'
import type { PlansRow } from './planView'
import { WAVE_OVERRIDE_STORAGE_KEY, createWaveOverrideStore, type WaveOverrideStore } from './waveOverrides'

/**
 * ENC-TSK-S98-0B (ENC-PLN-108 W3.2): the Plans page rendered from the W3.1 golden fixtures.
 *
 * AC-1 is checked STRUCTURALLY: the canvas's class names, nesting, data-state / data-open / data-role attributes and ARIA are
 * asserted below, and the container-query boundaries are checked by cascading plans.css at each width in plans.css.test.ts.
 * No pixel is compared: jsdom lays nothing out, so a visual match with the artboard at 390px and at desktop width is
 * unverified here.
 */
vi.mock('@tanstack/react-query', () => ({ useQuery: () => ({ data: [] }) }))
vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, className, params }: { children: unknown; className?: string; params?: { id?: string } }) => (
    <a href={`#${params?.id ?? ''}`} className={className}>
      {children as never}
    </a>
  ),
}))
vi.mock('../api/projectRegistry', () => ({ projectRegistryQueryOptions: {} }))
vi.mock('../routes/recordLink', () => ({ resolveRecordTarget: (id: string) => ({ to: '/t', params: { id } }) }))

const memory = () => {
  const data = new Map<string, string>()
  return { data, getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v) }
}

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
  window.localStorage.removeItem(WAVE_OVERRIDE_STORAGE_KEY)
})

const show = (corpus: readonly PlansRow[], store: WaveOverrideStore, extra: Partial<Parameters<typeof PlansPage>[0]> = {}) =>
  act(() => root.render(<PlansPage corpus={corpus} now={DEMO_NOW} asOf={DEMO_NOW} overrideStore={store} {...extra} />))
const q = <T extends Element = HTMLElement>(sel: string, from: ParentNode = container): T => {
  const el = from.querySelector<T>(sel)
  if (!el) throw new Error(`missing ${sel}`)
  return el
}
const qa = (sel: string, from: ParentNode = container): HTMLElement[] => [...from.querySelectorAll<HTMLElement>(sel)]
const click = (el: Element) => act(() => (el as HTMLElement).click())
const waveRow = (card: ParentNode, tag: string): HTMLElement => {
  const row = qa('.pl-wave', card).find((r) => r.querySelector('.pl-wtag')?.textContent === tag)
  if (!row) throw new Error(`no wave ${tag}`)
  return row
}
const toggleOf = (card: ParentNode, tag: string) => q<HTMLButtonElement>('.pl-toggle', waveRow(card, tag))
const bodyOf = (card: ParentNode, tag: string) => waveRow(card, tag).nextElementSibling as HTMLElement
/** Tag and class tree, without text, ids or styles: what a layout would see. */
const skeleton = (el: Element): string => `${el.tagName.toLowerCase()}.${[...el.classList].join('.')}[${[...el.children].map(skeleton).join(',')}]`

describe('structure of Main.dc.html (acceptance criterion 1, structural)', () => {
  it('draws the header: PageHeader with the count, freshness in Pacific, the refresh control and the project filter', () => {
    show(buildDemoCorpus(), createWaveOverrideStore(() => null))
    const head = q('.pl > .pl-head')
    expect(q('.pl-head__title [data-page-header] h1', head).textContent).toBe('Plans (10)')
    expect(q('.pl-tools .pl-fresh', head).textContent).toBe('current as of 16:00:00 PST')
    expect(q('.pl-fresh', head).title).toBe('Corpus lastSeededAt: moves on every heal')
    expect(q('.pl-tools button.pl-iconbtn', head).getAttribute('aria-label')).toBe('Refresh the corpus')
    expect(q('.pl-tools .pl-filter .ev2-select__value', head).textContent).toBe('All projects')
  })

  it('draws the legend as a labelled list of seven marks, in the canvas order', () => {
    show(buildDemoCorpus(), createWaveOverrideStore(() => null))
    const legend = q('ul.pl-legend')
    expect(legend.getAttribute('aria-label')).toBe('How to read a lane')
    const items = qa('li', legend)
    expect(items.map((li) => li.textContent)).toEqual(['Created', 'Waiting for checkout', 'Checked out to closed', 'Checked out, still open', 'Closed', 'Wave window', 'Folded idle gap'])
    expect(items.map((li) => q('.pl-key > span', li).className)).toEqual(['pl-c', 'pl-wait', 'pl-work', 'pl-work', 'pl-z', 'pl-band', 'pl-gap'])
    expect(qa('.pl-key > .pl-work').map((m) => [m.dataset.role, m.dataset.open])).toEqual([['done', undefined], ['active', 'true']])
  })

  it('draws one section.pl-card per plan with its id as anchor and label, newest first, and no entry animation class', () => {
    show(buildDemoCorpus(), createWaveOverrideStore(() => null))
    const cards = qa('.pl-list > section.pl-card')
    expect(cards).toHaveLength(10)
    expect(cards.slice(0, 3).map((c) => c.id)).toEqual(['ENC-PLN-106', 'FIN-PLN-009', 'INT-PLN-031'])
    expect(cards.every((c) => c.getAttribute('aria-label') === c.id)).toBe(true)
    // pl-enter is the W4 entry animation, put on an ADDED card by the change set; a cold load carries none.
    expect(container.querySelector('.pl-enter')).toBeNull()
  })

  it('draws the card: id link with copy button, project tag, created time, title, status pill, tally', () => {
    show(buildDemoCorpus(), createWaveOverrideStore(() => null))
    const card = q('#FIN-PLN-009')
    expect([...card.children].map((c) => c.className)).toEqual(['pl-card__top', 'pl-card__title', 'pl-card__chips', 'pl-lanes'])
    const top = q('.pl-card__top', card)
    expect(q('a.enc-id', top).textContent).toBe('FIN-PLN-009')
    expect(q('a.enc-id', top).nextElementSibling?.getAttribute('aria-label')).toBe('Copy FIN-PLN-009')
    expect(q('.enc-tag[data-kind="code"]', top).textContent).toBe('finance')
    expect(q('time', top).textContent).toBe('created Nov 13 15:31 PST')
    expect(q('h2.pl-card__title', card).textContent).toContain('FIN-PLN-009')
    const chips = q('.pl-card__chips', card)
    expect([q('.enc-pill', chips).dataset.role, q('.enc-pill', chips).textContent]).toEqual(['active', 'started'])
    expect(q('p.pl-sum', chips).textContent).toBe('15 tree tasks in 5 waves, 9 closed · span 17h 54m · median wait 24m, work 13m')
    expect(qa('p.pl-sum b', chips)).toHaveLength(6)
  })

  it('draws the lanes: overlay, axis row, then each wave header followed by its body', () => {
    show(buildDemoCorpus(), createWaveOverrideStore(() => null))
    const lanes = q('#FIN-PLN-009 .pl-lanes')
    expect([...lanes.children].map((c) => c.className)).toEqual([
      'pl-over',
      'pl-row pl-axis',
      ...Array.from({ length: 5 }, () => ['pl-row pl-wave', 'pl-body']).flat(),
    ])
    const over = q('.pl-over', lanes)
    expect(over.getAttribute('aria-hidden')).toBe('true')
    expect(qa('.pl-grid', over).length).toBeGreaterThan(0)
    expect(qa('.pl-gap', over)).toHaveLength(3)
    expect(qa('.pl-now', over)).toHaveLength(1)
    const axis = q('.pl-axis', lanes)
    expect([...axis.children].map((c) => c.className)).toEqual(['pl-lab', 'pl-track', 'pl-dur'])
    expect(q('.pl-lab', axis).textContent).toBe('Wave / task')
    expect(q('.pl-track', axis).getAttribute('aria-hidden')).toBe('true')
    expect(qa('.pl-day', axis).map((d) => d.textContent)).toEqual(['Nov 13', 'Nov 14', 'now'])
    expect(qa('.pl-day', axis).map((d) => [d.style.left, d.style.right])).toEqual([['0%', ''], ['46.5%', ''], ['', '0px']])
    expect(qa('.pl-tick', axis).map((t) => t.textContent)).toEqual(['16:00', '3h 18m', '20:00', '8h 2m', '06:00', '08:00', '4d 6h'])
    expect(qa('.pl-tick[data-fold="true"]', axis)).toHaveLength(3)
    expect(qa('.pl-dur span', axis).map((s) => s.textContent)).toEqual(['wait', 'work'])
  })

  it('draws a wave header: toggle button (chevron, tag), title, tally pill by state, band on the track, window in the last column', () => {
    show(buildDemoCorpus(), createWaveOverrideStore(() => null))
    const card = q('#ENC-PLN-106')
    const row = waveRow(card, 'W0')
    expect(row.className).toBe('pl-row pl-wave')
    expect(row.dataset.state).toBe('done')
    expect([...row.children].map((c) => c.className)).toEqual(['pl-lab', 'pl-track', 'pl-dur'])
    const lab = q('.pl-lab', row)
    expect([...lab.children].map((c) => c.className)).toEqual(['pl-toggle', 'enc-id', 'pl-ttl', 'enc-pill'])
    const button = q<HTMLButtonElement>('button.pl-toggle', lab)
    expect(button.type).toBe('button')
    expect(button.getAttribute('aria-expanded')).toBe('false')
    expect(button.getAttribute('aria-label')).toBe('Expand wave W0, done, 1 of 1 closed')
    expect([...button.children].map((c) => c.tagName.toLowerCase() + '.' + c.getAttribute('class'))).toEqual(['svg.pl-chev', 'span.pl-wtag'])
    expect(q('svg.pl-chev', button).getAttribute('aria-hidden')).toBe('true')
    expect(q('a.enc-id', lab).getAttribute('href')).toBe('#ENC-TSK-S59')
    expect(q('.pl-ttl', lab).textContent).toBe('DS v1.1 W0 -- Baseline and decisions')
    expect([q('.enc-pill', lab).dataset.role, q('.enc-pill', lab).textContent]).toEqual(['done', '1 of 1'])
    expect(q('.pl-track .pl-band', row).dataset.open).toBeUndefined()
    expect(qa('.pl-dur span', row).map((s) => s.textContent)).toEqual(['', '23m'])
  })

  it('draws a task lane: wait line, work bar by status role, creation ring, close dot, durations', () => {
    show(buildDemoCorpus(), createWaveOverrideStore(() => null))
    const card = q('#FIN-PLN-009')
    const lane = (id: string) => qa('.pl-task', card).find((r) => r.querySelector('.pl-lab .enc-id')?.textContent === id) as HTMLElement
    const closed = lane('FIN-TSK-259')
    expect([...closed.children].map((c) => c.className)).toEqual(['pl-lab', 'pl-track', 'pl-dur'])
    expect([...q('.pl-lab', closed).children].map((c) => c.className)).toEqual(['enc-id', 'pl-ttl'])
    expect([...q('.pl-track', closed).children].map((c) => c.className)).toEqual(['pl-wait', 'pl-work', 'pl-c', 'pl-z'])
    expect(q('.pl-work', closed).dataset.role).toBe('done')
    expect(q('.pl-work', closed).dataset.open).toBeUndefined()
    expect(qa('.pl-dur span', closed).map((s) => s.textContent)).toEqual(['40m', '5h 23m'])
    expect(closed.title).toBe('closed · created Nov 13 15:31 · first checkout Nov 13 16:11 · closed Nov 13 21:34')

    const inFlight = lane('FIN-TSK-261')
    expect([...q('.pl-track', inFlight).children].map((c) => c.className)).toEqual(['pl-wait', 'pl-work', 'pl-c'])
    expect([q('.pl-work', inFlight).dataset.role, q('.pl-work', inFlight).dataset.open]).toEqual(['active', 'true'])
    expect(qa('.pl-dur span', inFlight).map((s) => s.textContent)).toEqual(['1h 7m', 'open'])

    const waiting = lane('FIN-TSK-266')
    expect([...q('.pl-track', waiting).children].map((c) => [c.className, (c as HTMLElement).dataset.open])).toEqual([['pl-wait', 'true'], ['pl-c', undefined]])
  })

  it('draws a checked-out task without stamps as a ring and its status pill, as States.dc.html does', () => {
    const rows: PlansRow[] = [
      { item_id: 'SYN-PLN-001', record_type: 'plan', title: 'Synthetic', project_id: 'synthetic', status: 'started', created_at: '2026-11-10T00:00:00Z', objectives_set: ['SYN-TSK-1'] },
      { item_id: 'SYN-TSK-1', record_type: 'task', title: 'W1 before the backfill', status: 'in-progress', created_at: '2026-11-10T01:00:00Z' },
    ]
    show(rows, createWaveOverrideStore(() => null))
    const lane = q('.pl-task')
    expect([...q('.pl-lab', lane).children].map((c) => c.className)).toEqual(['enc-id', 'pl-ttl', 'enc-pill'])
    expect([q('.pl-lab .enc-pill', lane).dataset.role, q('.pl-lab .enc-pill', lane).textContent]).toEqual(['active', 'in progress'])
    expect([...q('.pl-track', lane).children].map((c) => c.className)).toEqual(['pl-c'])
    expect(q('.pl-wave').dataset.state).toBe('active')
  })

  it('draws the plan chips (D-7) and the objectives outside the corpus', () => {
    const { corpus } = demoPlan('FIN-PLN-010')
    const card = q('.pl-card', (() => (show(corpus, createWaveOverrideStore(() => null)), container))())
    expect(qa('.pl-card__chips .enc-tag[data-kind="code"]', card).map((t) => t.textContent)).toEqual(['FIN-FTR-027', 'FIN-FTR-028'])
    const gone = corpus.filter((r) => r.item_id !== 'FIN-FTR-027')
    show(gone, createWaveOverrideStore(() => null))
    expect(qa('.pl-card__chips .enc-tag').map((t) => t.textContent)).toEqual(['FIN-FTR-028'])
    expect(q('.pl-card__chips .pl-absent').textContent).toBe('1 objective is outside the corpus')
  })

  it('has the same markup at a phone width and at a desktop width: the layout switch is the container query, not the DOM', () => {
    const phone = document.createElement('div')
    phone.style.width = '342px'
    const desktop = document.createElement('div')
    desktop.style.width = '1072px'
    document.body.append(phone, desktop)
    const a = createRoot(phone)
    const b = createRoot(desktop)
    const store = () => createWaveOverrideStore(() => null)
    act(() => a.render(<PlansPage corpus={buildDemoCorpus()} now={DEMO_NOW} asOf={DEMO_NOW} overrideStore={store()} />))
    act(() => b.render(<PlansPage corpus={buildDemoCorpus()} now={DEMO_NOW} asOf={DEMO_NOW} overrideStore={store()} />))
    expect(skeleton(q('.pl', phone))).toBe(skeleton(q('.pl', desktop)))
    // Every row carries all three cells at both widths; below 880px of card the third is display: none in CSS.
    for (const host of [phone, desktop]) {
      expect(qa('.pl-row', host).every((r) => [...r.children].map((c) => c.className).join('|') === 'pl-lab|pl-track|pl-dur')).toBe(true)
    }
    act(() => a.unmount())
    act(() => b.unmount())
    phone.remove()
    desktop.remove()
  })
})

describe('collapse and default rules (R7 to R10)', () => {
  it('opens a hot wave of a started plan and collapses the rest, with the body inert while closed', () => {
    show(buildDemoCorpus(), createWaveOverrideStore(() => null))
    const card = q('#FIN-PLN-009')
    const view = ['W0', 'W1', 'W2', 'W3', 'none'].map((t) => [t, toggleOf(card, t).getAttribute('aria-expanded'), bodyOf(card, t).dataset.open, bodyOf(card, t).hasAttribute('inert')])
    expect(view).toEqual([
      ['W0', 'false', 'false', true],
      ['W1', 'true', 'true', false],
      ['W2', 'true', 'true', false],
      ['W3', 'false', 'false', true],
      ['none', 'true', 'true', false],
    ])
    expect(toggleOf(card, 'W1').getAttribute('aria-label')).toBe('Collapse wave W1, active, 2 of 3 closed')
    expect(toggleOf(card, 'W1').getAttribute('aria-controls')).toBe(bodyOf(card, 'W1').id)
    expect(q('.pl-band', waveRow(card, 'W1')).dataset.open).toBe('true')
    expect(q('.pl-wave[data-state="todo"]', card)).toBe(waveRow(card, 'W3'))
  })

  it('collapses everything on a drafted plan, whatever is hot (R7), and on a complete one', () => {
    const { plan, corpus } = demoPlan('FIN-PLN-009')
    show(corpus.map((r) => (r === plan ? { ...r, status: 'drafted' } : r)), createWaveOverrideStore(() => null))
    expect(qa('.pl-toggle').map((b) => b.getAttribute('aria-expanded'))).toEqual(['false', 'false', 'false', 'false', 'false'])
    expect(qa('.pl-wave').map((r) => r.dataset.state)).toEqual(['done', 'active', 'active', 'todo', 'active'])
    show(demoPlan('ENC-PLN-106').corpus, createWaveOverrideStore(() => null))
    expect(qa('.pl-toggle').every((b) => b.getAttribute('aria-expanded') === 'false')).toBe(true)
  })
})

describe('the wave toggle (acceptance criterion 3)', () => {
  it('toggles on a click of the button and sets aria-expanded, aria-label and the body together', () => {
    show(buildDemoCorpus(), createWaveOverrideStore(() => memory()))
    const card = q('#FIN-PLN-009')
    click(toggleOf(card, 'W0'))
    expect(toggleOf(card, 'W0').getAttribute('aria-expanded')).toBe('true')
    expect(toggleOf(card, 'W0').getAttribute('aria-label')).toBe('Collapse wave W0, done, 3 of 3 closed')
    expect([bodyOf(card, 'W0').dataset.open, bodyOf(card, 'W0').hasAttribute('inert')]).toEqual(['true', false])
    click(toggleOf(card, 'W1'))
    expect(toggleOf(card, 'W1').getAttribute('aria-expanded')).toBe('false')
    expect(bodyOf(card, 'W1').hasAttribute('inert')).toBe(true)
  })

  it('does NOT toggle when the wave parent link is clicked: the link is a sibling of the button, above its overlay', () => {
    show(demoPlan('ENC-PLN-106').corpus, createWaveOverrideStore(() => memory()))
    const card = q('#ENC-PLN-106')
    const row = waveRow(card, 'W0')
    const link = q<HTMLAnchorElement>('a.enc-id', row)
    const button = toggleOf(card, 'W0')
    expect(button.contains(link)).toBe(false)
    expect(link.parentElement).toBe(button.parentElement)
    click(link)
    expect(button.getAttribute('aria-expanded')).toBe('false')
    expect(bodyOf(card, 'W0').dataset.open).toBe('false')
    // A click anywhere else on the row lands on the button's ::after overlay, which is the button itself.
    click(button)
    expect(button.getAttribute('aria-expanded')).toBe('true')
    click(link)
    expect(button.getAttribute('aria-expanded')).toBe('true')
  })

  it('does not toggle when a task link or the plan link is clicked, and the copy button is not inside a toggle', () => {
    show(buildDemoCorpus(), createWaveOverrideStore(() => memory()))
    const card = q('#FIN-PLN-009')
    const before = qa('.pl-toggle', card).map((b) => b.getAttribute('aria-expanded'))
    for (const a of qa('a.enc-id', card)) click(a)
    expect(qa('.pl-toggle', card).map((b) => b.getAttribute('aria-expanded'))).toEqual(before)
    expect(qa('button.pl-toggle', card).every((b) => !b.querySelector('a, button'))).toBe(true)
  })
})

describe('manual toggles persist per device until the wave changes (acceptance criterion 4, ruling D-3)', () => {
  const plan: PlansRow = { item_id: 'SYN-PLN-001', record_type: 'plan', title: 'Synthetic', project_id: 'synthetic', status: 'started', created_at: '2026-11-10T00:00:00Z', objectives_set: ['SYN-TSK-P'] }
  const parent: PlansRow = { item_id: 'SYN-TSK-P', record_type: 'task', title: 'W1 Parent', status: 'in-progress', created_at: '2026-11-10T01:00:00Z' }
  const child = (extra: Partial<PlansRow>): PlansRow => ({ item_id: 'SYN-TSK-P-0A', record_type: 'task', title: 'child', parent: 'SYN-TSK-P', created_at: '2026-11-10T01:00:00Z', ...extra })
  /** todo: never checked out, nothing hot. */
  const todo = [plan, parent, child({ status: 'open' })]
  /** active and hot: checked out and open. */
  const hot = [plan, parent, child({ status: 'in-progress', first_checked_out_at: '2026-11-10T02:00:00Z' })]
  /** active, not hot (D-2, settling): the member closed, the parent still open. Same state as `hot`, different hotness. */
  const settling = [plan, parent, child({ status: 'closed', first_checked_out_at: '2026-11-10T02:00:00Z', closed_at: '2026-11-10T03:00:00Z' })]
  const KEY = 'SYN-PLN-001/W1'
  const open = () => toggleOf(container, 'W1').getAttribute('aria-expanded')

  it('keeps a toggle across a reload of the page on the same device (a new store over the same localStorage)', () => {
    const storage = memory()
    show(todo, createWaveOverrideStore(() => storage))
    expect(open()).toBe('false')
    click(toggleOf(container, 'W1'))
    expect(open()).toBe('true')
    expect(JSON.parse(storage.data.get(WAVE_OVERRIDE_STORAGE_KEY) as string)).toEqual({ [KEY]: { expanded: true, state: 'todo', hot: false } })
    act(() => root.unmount())
    root = createRoot(container)
    show(todo, createWaveOverrideStore(() => storage))
    expect(open()).toBe('true')
  })

  it('discards the toggle when the wave changes STATE (todo to active) and does not bring it back when the state returns', () => {
    const store = createWaveOverrideStore(() => memory())
    show(todo, store)
    click(toggleOf(container, 'W1'))
    expect(open()).toBe('true')
    expect(store.getSnapshot()[KEY]).toEqual({ expanded: true, state: 'todo', hot: false })
    show(hot, store)
    expect(open()).toBe('true') // hot on a started plan: open by default now
    expect(store.getSnapshot()[KEY]).toBeUndefined()
    show(todo, store)
    expect(open()).toBe('false') // the click made under `todo` earlier is gone: the default rules again
  })

  it('discards the toggle when the wave changes HOTNESS with the state unchanged (hot to settling) and does not bring it back', () => {
    const store = createWaveOverrideStore(() => memory())
    show(hot, store)
    expect(open()).toBe('true')
    click(toggleOf(container, 'W1'))
    expect(open()).toBe('false')
    expect(store.getSnapshot()[KEY]).toEqual({ expanded: false, state: 'active', hot: true })
    show(settling, store)
    expect(waveRow(container, 'W1').dataset.state).toBe('active')
    expect(store.getSnapshot()[KEY]).toBeUndefined()
    show(hot, store)
    expect(open()).toBe('true') // the collapse made while hot did not outlive the change
  })

  it('holds the toggle while nothing about the wave changes, across other changes on the page', () => {
    const store = createWaveOverrideStore(() => memory())
    show(hot, store)
    click(toggleOf(container, 'W1'))
    show(hot.map((r) => (r.item_id === 'SYN-TSK-P-0A' ? { ...r, title: 'renamed' } : r)), store)
    expect(open()).toBe('false')
    expect(store.getSnapshot()[KEY]).toBeDefined()
  })

  it('renders correctly when localStorage throws on every read and write, and the toggle still works for the session', () => {
    const throwing = {
      getItem: () => {
        throw new Error('SecurityError')
      },
      setItem: () => {
        throw new Error('QuotaExceededError')
      },
    }
    show(hot, createWaveOverrideStore(() => throwing))
    expect(open()).toBe('true')
    click(toggleOf(container, 'W1'))
    expect(open()).toBe('false')
  })

  it('uses the device store, window.localStorage, when none is given', () => {
    act(() => root.render(<PlansPage corpus={hot} now={DEMO_NOW} />))
    click(toggleOf(container, 'W1'))
    expect(JSON.parse(window.localStorage.getItem(WAVE_OVERRIDE_STORAGE_KEY) as string)).toEqual({ [KEY]: { expanded: false, state: 'active', hot: true } })
  })
})

describe('the rest of the page', () => {
  const store = () => createWaveOverrideStore(() => null)

  it('filters by project with the Select and resets to the first page', () => {
    show(buildDemoCorpus(), store())
    click(q('.ev2-select__trigger'))
    expect(qa('.ev2-select__opt').map((o) => o.textContent)).toEqual(['All projects', 'devops', 'enceladus', 'finance', 'harrisonfamily', 'intelligence', 'tracker'])
    click(qa('.ev2-select__opt').find((o) => o.textContent === 'finance') as HTMLElement)
    expect(qa('.pl-card').map((c) => c.id)).toEqual(['FIN-PLN-009', 'FIN-PLN-010'])
    expect(q('[data-page-header] h1').textContent).toBe('Plans (2)')
    expect(q('.ev2-select__value').textContent).toBe('finance')
  })

  it('says so when a project has no plans', () => {
    show([], store())
    expect(q('.pl-list .pl-empty').textContent).toBe('No plans in this project.')
    expect(container.querySelector('.pl-foot')).toBeNull()
  })

  it('shows the newest 20 plans and a button for the next page (D-9)', () => {
    const rows: PlansRow[] = Array.from({ length: 25 }, (_, i) => ({
      item_id: `SYN-PLN-${String(i + 1).padStart(3, '0')}`,
      record_type: 'plan',
      title: `Plan ${i + 1}`,
      project_id: 'synthetic',
      status: 'drafted',
      created_at: new Date(Date.UTC(2026, 10, 1, 0, i)).toISOString(),
      objectives_set: [],
    }))
    show(rows, store())
    expect(qa('.pl-card')).toHaveLength(20)
    expect(qa('.pl-card')[0]?.id).toBe('SYN-PLN-025')
    expect(q('.pl-foot button').textContent).toBe('Show 5 older plans')
    click(q('.pl-foot button'))
    expect(qa('.pl-card')).toHaveLength(25)
    expect(container.querySelector('.pl-foot')).toBeNull()
  })

  it('calls onRefresh from the refresh control', () => {
    const onRefresh = vi.fn()
    show(buildDemoCorpus(), store(), { onRefresh })
    click(q('.pl-iconbtn'))
    expect(onRefresh).toHaveBeenCalledTimes(1)
  })

  it('marks the freshness dot stale, and omits the freshness text when there is no corpus time', () => {
    show(buildDemoCorpus(), store(), { stale: true })
    expect(q('.pl-fresh').dataset.stale).toBe('true')
    show(buildDemoCorpus(), store(), { asOf: null })
    expect(container.querySelector('.pl-fresh')).toBeNull()
  })

  it('shows a SkeletonCard while loading and an Alert on error, instead of the list', () => {
    show([], store(), { loading: true })
    expect(q('[role="status"][aria-busy="true"]').getAttribute('aria-label')).toBe('Loading plans')
    expect(container.querySelector('.pl-list')).toBeNull()
    show([], store(), { error: 'The corpus is unreachable.' })
    expect(q('[role="alert"]').textContent).toContain('Plans could not be loaded')
    expect(q('[role="alert"]').textContent).toContain('The corpus is unreachable.')
    expect(container.querySelector('[aria-busy]')).toBeNull()
  })
})
