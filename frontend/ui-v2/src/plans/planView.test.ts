import { describe, expect, it } from 'vitest'
import { buildDemoCorpus, DEMO_NOW, demoPlan } from './__fixtures__/demoCorpus'
import { buildPlanView, type PlansRow } from './planView'

const iso = (d: number, hm: string): string => `2026-11-${String(d).padStart(2, '0')}T${hm}:00.000Z`
const plan = (status: string, objectives: string[]): PlansRow => ({
  item_id: 'SYN-PLN-001',
  record_type: 'plan',
  title: 'Synthetic',
  project_id: 'synthetic',
  status,
  created_at: iso(10, '00:00'),
  objectives_set: objectives,
})
const task = (item_id: string, extra: Partial<PlansRow> = {}): PlansRow => ({ item_id, record_type: 'task', title: `${item_id} title`, status: 'open', created_at: iso(10, '01:00'), ...extra })

describe('buildPlanView from the golden fixtures (the canvas stamps)', () => {
  it('F7 FIN-PLN-009: four numbered waves, then Unassigned drawn as a wave tagged none (D-20)', () => {
    const { plan: p, corpus } = demoPlan('FIN-PLN-009')
    const v = buildPlanView(p, corpus, DEMO_NOW)
    expect(v.waves.map((w) => [w.tag, w.state, w.hot, w.tally])).toEqual([
      ['W0', 'done', false, '3 of 3'],
      ['W1', 'active', true, '2 of 3'],
      ['W2', 'active', true, '2 of 4'],
      ['W3', 'todo', false, '0 of 1'],
      ['none', 'active', true, '2 of 4'],
    ])
    expect(v.waves[4]?.unassigned).toBe(true)
    expect(v.waves.map((w) => w.key)).toEqual(['FIN-PLN-009/W0', 'FIN-PLN-009/W1', 'FIN-PLN-009/W2', 'FIN-PLN-009/W3', 'FIN-PLN-009/unassigned'])
    expect(v.stats).toMatchObject({ nTasks: 15, nWaves: 5, nClosed: 9, hasStats: true })
  })

  it('F7: the canvas lane of FIN-TSK-259 prints 40m of wait and 5h 23m of work, and open bars run to the right edge', () => {
    const { plan: p, corpus } = demoPlan('FIN-PLN-009')
    const v = buildPlanView(p, corpus, DEMO_NOW)
    const closed = v.waves[1]?.tasks.find((t) => t.id === 'FIN-TSK-259')
    expect([closed?.waitText, closed?.workText, closed?.work?.role, closed?.work?.open]).toEqual(['40m', '5h 23m', 'done', false])
    expect(closed?.closedPct).not.toBeNull()
    const open = v.waves[1]?.tasks.find((t) => t.id === 'FIN-TSK-261')
    expect([open?.workText, open?.work?.role, open?.work?.open, open?.closedPct]).toEqual(['open', 'active', true, null])
    expect((open?.work?.leftPct ?? 0) + (open?.work?.widthPct ?? 0)).toBeCloseTo(100, 5)
    expect(v.axis.hasNow).toBe(true)
    expect(v.axis.days.at(-1)).toEqual({ label: 'now', leftPct: null })
  })

  it('F7: a task never checked out on a started plan waits on a dashed line to the edge; a drafted plan draws only the ring', () => {
    const { plan: p, corpus } = demoPlan('FIN-PLN-009')
    const w3 = buildPlanView(p, corpus, DEMO_NOW).waves[3]?.tasks[0]
    expect(w3?.wait).toMatchObject({ open: true })
    expect((w3?.wait?.leftPct ?? 0) + (w3?.wait?.widthPct ?? 0)).toBeCloseTo(100, 5)
    expect(w3?.work).toBeNull()
    const drafted = buildPlanView({ ...p, status: 'drafted' }, corpus, DEMO_NOW).waves[3]?.tasks[0]
    expect(drafted?.wait).toBeNull()
    expect(drafted?.createdPct).not.toBeNull()
  })

  it('F4 ENC-PLN-106: every wave is done with a closed window, and a wave parent supplies the title and the link', () => {
    const { plan: p, corpus } = demoPlan('ENC-PLN-106')
    const v = buildPlanView(p, corpus, DEMO_NOW)
    expect(v.waves.map((w) => [w.tag, w.state, w.parentId])).toEqual([
      ['W0', 'done', 'ENC-TSK-S59'],
      ['W1', 'done', 'ENC-TSK-S60'],
      ['W2', 'done', 'ENC-TSK-S61'],
      ['W3', 'done', 'ENC-TSK-S62'],
      ['W4', 'done', 'ENC-TSK-S63'],
      ['W5', 'done', 'ENC-TSK-S64'],
      ['W6', 'done', 'ENC-TSK-S65'],
    ])
    expect(v.waves[0]?.title).toBe('DS v1.1 W0 -- Baseline and decisions')
    expect(v.waves.every((w) => w.band !== null && w.band.open === false && w.windowText !== 'open')).toBe(true)
    expect(v.axis.hasNow).toBe(false)
    expect(v.stats.nTasks).toBe(13)
  })

  it('F10 INT-PLN-031: a wave nothing has touched is todo with no window; a wave founded by a childless objective is a parentless wave', () => {
    const { plan: p, corpus } = demoPlan('INT-PLN-031')
    const v = buildPlanView(p, corpus, DEMO_NOW)
    const w7 = v.waves.find((w) => w.tag === 'W7')
    expect([w7?.state, w7?.tally, w7?.parentId, w7?.band, w7?.windowText, w7?.title]).toEqual(['todo', '0 of 1', null, null, '', 'grouped by objective title'])
    const w3 = v.waves.find((w) => w.tag === 'W3')
    expect([w3?.state, w3?.windowText, w3?.band?.open]).toEqual(['done', '1h 6m', false])
  })

  it('every position is inside the track, for every golden fixture', () => {
    for (const row of buildDemoCorpus().filter((r) => r.record_type === 'plan')) {
      const v = buildPlanView(row, buildDemoCorpus(), DEMO_NOW)
      for (const w of v.waves) {
        for (const b of [w.band, ...w.tasks.flatMap((t) => [t.wait, t.work])]) {
          if (!b) continue
          expect(b.leftPct).toBeGreaterThanOrEqual(0)
          expect(b.widthPct).toBeGreaterThanOrEqual(0)
          expect(b.leftPct + b.widthPct).toBeLessThanOrEqual(100.0001)
        }
      }
    }
  })
})

describe('buildPlanView, the cases of States.dc.html', () => {
  it('settling (D-2): every member closed and the parent open keeps the active state, nothing is hot, the window is closed', () => {
    const rows = [
      task('SYN-TSK-1', { title: 'W1 Parent', status: 'in-progress', created_at: iso(10, '01:00') }),
      task('SYN-TSK-1-0A', { parent: 'SYN-TSK-1', status: 'closed', created_at: iso(10, '01:00'), first_checked_out_at: iso(10, '01:20'), closed_at: iso(10, '02:00') }),
    ]
    const w = buildPlanView(plan('started', ['SYN-TSK-1']), rows, iso(11, '00:00')).waves[0]
    expect([w?.state, w?.hot, w?.settling, w?.tally, w?.band?.open, w?.windowText]).toEqual(['active', false, true, '1 of 1', false, '40m'])
    expect(w?.ariaLabel(false)).toBe('Expand wave W1, active, 1 of 1 closed, waiting for its parent to close')
    expect(w?.ariaLabel(true)).toBe('Collapse wave W1, active, 1 of 1 closed, waiting for its parent to close')
  })

  it('a task checked out before the backfill keeps its ring and shows its status pill, with no bar and no wait line', () => {
    const rows = [task('SYN-TSK-2', { title: 'W1 Early', status: 'in-progress', created_at: iso(10, '01:00') })]
    const t = buildPlanView(plan('started', ['SYN-TSK-2']), rows, iso(11, '00:00')).waves[0]?.tasks[0]
    expect([t?.showStatusPill, t?.wait, t?.work, t?.closedPct, t?.workText]).toEqual([true, null, null, null, ''])
    expect(t?.createdPct).not.toBeNull()
  })

  it('the bar colour is the status role: pr is waiting, coding-updates is caution, in-progress is active', () => {
    const base = { created_at: iso(10, '01:00'), first_checked_out_at: iso(10, '02:00') }
    const rows = [
      task('SYN-TSK-3', { title: 'W1 a', status: 'pr', ...base }),
      task('SYN-TSK-4', { title: 'W1 b', status: 'coding-updates', ...base }),
      task('SYN-TSK-5', { title: 'W1 c', status: 'in-progress', ...base }),
    ]
    const v = buildPlanView(plan('started', ['SYN-TSK-3', 'SYN-TSK-4', 'SYN-TSK-5']), rows, iso(11, '00:00'))
    expect(v.waves[0]?.tasks.map((t) => t.work?.role)).toEqual(['waiting', 'caution', 'active'])
  })

  it('a closed task whose close stamp is missing draws no bar rather than an open one, and keeps its status', () => {
    const rows = [task('SYN-TSK-6', { title: 'W1 old', status: 'closed', first_checked_out_at: iso(10, '02:00') })]
    const t = buildPlanView(plan('started', ['SYN-TSK-6']), rows, iso(11, '00:00')).waves[0]?.tasks[0]
    expect([t?.work, t?.closedPct, t?.status]).toEqual([null, null, 'closed'])
  })

  it('non-task objectives become code chips and unknown objectives are counted, never placed (D-7)', () => {
    const rows = [task('SYN-TSK-7', { title: 'W1 x' }), { item_id: 'SYN-FTR-1', record_type: 'feature', title: 'A feature', status: 'open' } as PlansRow]
    const v = buildPlanView(plan('started', ['SYN-TSK-7', 'SYN-FTR-1', 'SYN-TSK-GONE']), rows, iso(11, '00:00'))
    expect([v.chips, v.missing]).toEqual([['SYN-FTR-1'], 1])
  })

  it('prints times in Pacific: created text and the tooltip of a lane', () => {
    const { plan: p, corpus } = demoPlan('FIN-PLN-009')
    const v = buildPlanView(p, corpus, DEMO_NOW)
    expect(v.createdText).toBe('Nov 13 15:31 PST')
    expect(v.waves[0]?.tasks[0]?.tip).toBe('closed · created Nov 13 15:31 · first checkout Nov 13 15:39 · closed Nov 13 15:51')
  })
})
