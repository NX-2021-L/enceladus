/**
 * ENC-TSK-S98-0B (ENC-PLN-108 W3.2): a corpus to render the page from, built on the W3.1 golden fixtures.
 *
 * The golden fixtures pin the RESOLVER: objectives, parent pointers and titles, with no plan row and no lifecycle stamps.
 * The page also needs a plan row (title, status, project) and the stamps that put bars on the lanes, so this layers them on.
 * Three fixtures take the stamps of the approved canvas's own records (Main.dc.html: devops mart read of 2026-11-18T06:00Z),
 * keyed by id, so the rendered page can be compared with the lens artboard: F7 is FIN-PLN-009, F4 is ENC-PLN-106 and F10 is
 * INT-PLN-031. Titles stay the fixtures' own, because the resolver reads titles and the fixtures are its contract.
 *
 * Test data only: nothing in the app imports this module.
 */
import { GOLDEN_FIXTURES, type GoldenFixture } from '../lens/__fixtures__'
import type { PlansRow } from '../planView'

/** "DD HH:MM" in November 2026, UTC, as the canvas writes its times. */
const U = (s: string): string => {
  const d = Number(s.slice(0, 2))
  const h = Number(s.slice(3, 5))
  const m = Number(s.slice(6, 8))
  return new Date(Date.UTC(2026, 10, d, h, m)).toISOString()
}

/** The instant the canvas's mock is read at: Nov 19 00:00 UTC. Open bars run to it. */
export const DEMO_NOW = U('19 00:00')

type Stamp = readonly [status: string, created: string, checkedOut?: string, closed?: string]

const STAMPS: Record<string, Stamp> = {
  // F7, FIN-PLN-009
  'FIN-TSK-256': ['closed', '13 23:31', '13 23:39', '13 23:51'],
  'FIN-TSK-257': ['closed', '13 23:31', '13 23:39', '13 23:51'],
  'FIN-TSK-258': ['closed', '13 23:31', '13 23:39', '13 23:44'],
  'FIN-TSK-259': ['closed', '13 23:31', '14 00:11', '14 05:34'],
  'FIN-TSK-260': ['closed', '13 23:31', '14 00:11', '14 00:41'],
  'FIN-TSK-261': ['deploy-success', '13 23:31', '14 00:38'],
  'FIN-TSK-262': ['closed', '13 23:31', '14 13:56', '14 14:29'],
  'FIN-TSK-263': ['deploy-success', '13 23:31', '14 03:59'],
  'FIN-TSK-264': ['deploy-success', '13 23:31', '14 03:59'],
  'FIN-TSK-265': ['closed', '13 23:31', '14 04:37', '14 17:25'],
  'FIN-TSK-266': ['open', '13 23:31'],
  'FIN-TSK-267': ['closed', '14 04:21', '14 04:22', '14 04:31'],
  'FIN-TSK-268': ['closed', '14 05:09', '14 05:10', '14 05:23'],
  'FIN-TSK-269': ['deploy-success', '14 05:32', '14 05:34'],
  'FIN-TSK-270': ['deploy-success', '14 05:53', '14 05:54'],
  // F4, ENC-PLN-106: every wave parent and member is closed
  'ENC-TSK-S59': ['closed', '13 23:45', undefined, '14 00:34'],
  'ENC-TSK-S59-0A': ['closed', '13 23:47', '14 00:11', '14 00:33'],
  'ENC-TSK-S60': ['closed', '13 23:46', undefined, '14 00:42'],
  'ENC-TSK-S60-0A': ['closed', '13 23:47', '14 00:27', '14 00:41'],
  'ENC-TSK-S60-0B': ['closed', '13 23:47', '14 00:30', '14 00:41'],
  'ENC-TSK-S61': ['closed', '13 23:46', undefined, '14 04:12'],
  'ENC-TSK-S61-0A': ['closed', '13 23:47', '14 00:39', '14 03:57'],
  'ENC-TSK-S62': ['closed', '13 23:46', undefined, '14 04:12'],
  'ENC-TSK-S62-0A': ['closed', '13 23:47', '14 00:47', '14 03:58'],
  'ENC-TSK-S62-0B': ['closed', '13 23:47', '14 00:50', '14 03:58'],
  'ENC-TSK-S63': ['closed', '13 23:46', undefined, '14 04:12'],
  'ENC-TSK-S63-0A': ['closed', '13 23:48', '14 00:58', '14 03:58'],
  'ENC-TSK-S63-0B': ['closed', '13 23:48', '14 01:01', '14 03:58'],
  'ENC-TSK-S63-0C': ['closed', '13 23:48', '14 01:03', '14 03:58'],
  'ENC-TSK-S64': ['closed', '13 23:46', undefined, '14 04:12'],
  'ENC-TSK-S64-0A': ['closed', '13 23:47', '14 01:14', '14 03:58'],
  'ENC-TSK-S64-0B': ['closed', '13 23:47', '14 01:09', '14 01:23'],
  'ENC-TSK-S65': ['closed', '13 23:46', undefined, '14 04:13'],
  'ENC-TSK-S65-0A': ['closed', '13 23:48', '14 01:27', '14 04:12'],
  'ENC-TSK-S77': ['closed', '14 03:54', '14 03:54', '14 04:11'],
  // F10, INT-PLN-031: a drafted plan whose W3 alone was cut over and closed
  'INT-TSK-648': ['open', '11 00:49'],
  'INT-TSK-641-0A': ['open', '05 02:58'],
  'INT-TSK-648-0B': ['open', '11 05:32'],
  'INT-TSK-649': ['open', '11 00:49'],
  'INT-TSK-649-0A': ['open', '11 00:49'],
  'INT-TSK-643': ['closed', '05 02:57', undefined, '11 03:26'],
  'INT-TSK-643-0A': ['closed', '05 02:59', '11 02:20', '11 03:26'],
  'INT-TSK-644': ['open', '05 02:57'],
  'INT-TSK-644-0A': ['open', '05 03:00'],
  'INT-TSK-645': ['open', '05 02:57'],
  'INT-TSK-645-0A': ['open', '05 03:00'],
  'INT-TSK-646': ['open', '05 02:57'],
  'INT-TSK-646-0A': ['open', '05 03:00'],
  'INT-TSK-647': ['open', '05 02:57'],
}

/** Plan rows the canvas gives: status and created time. Every other fixture plan is a started plan created Nov 1 or earlier. */
const PLANS: Record<string, { status: string; created: string }> = {
  'FIN-PLN-009': { status: 'started', created: '13 23:31' },
  'ENC-PLN-106': { status: 'complete', created: '13 23:48' },
  'INT-PLN-031': { status: 'drafted', created: '11 00:50' },
}

const PROJECTS: Record<string, string> = {
  TRK: 'tracker',
  HFY: 'harrisonfamily',
  ENC: 'enceladus',
  DVP: 'devops',
  FIN: 'finance',
  INT: 'intelligence',
  SYN: 'synthetic',
}

/**
 * Plan rows plus every fixture row, with stamps where the canvas has them. By default the ten live fixtures: F11 is synthetic
 * and reuses F6's task ids with other parents, so the two cannot share one corpus (a corpus has one row per id).
 */
export function buildDemoCorpus(fixtures: readonly GoldenFixture[] = GOLDEN_FIXTURES.filter((f) => !f.synthetic)): PlansRow[] {
  const out: PlansRow[] = []
  fixtures.forEach((f, i) => {
    const project = PROJECTS[f.plan_id.slice(0, 3)] ?? 'enceladus'
    const plan = PLANS[f.plan_id]
    // Fixtures the canvas does not stamp are dated one day apart, newest first, so the order is the same on every run.
    const fallback = new Date(Date.UTC(2026, 9, 31 - i, 12, 0)).toISOString()
    out.push({
      item_id: f.plan_id,
      record_type: 'plan',
      title: f.name,
      project_id: project,
      status: plan?.status ?? 'started',
      created_at: plan ? U(plan.created) : fallback,
      objectives_set: f.objectives,
    })
    f.rows.forEach((row, j) => {
      const s = STAMPS[row.item_id]
      out.push({
        item_id: row.item_id,
        record_type: row.record_type,
        title: row.title ?? null,
        project_id: project,
        parent: row.parent ?? null,
        wave: row.wave ?? null,
        status: s ? s[0] : (row.status ?? 'open'),
        created_at: s ? U(s[1]) : new Date(Date.parse(fallback) + j * 60_000).toISOString(),
        first_checked_out_at: s?.[2] ? U(s[2]) : null,
        closed_at: s?.[3] ? U(s[3]) : null,
      })
    })
  })
  return out
}

/** One fixture's plan row and its own rows, for tests that draw a single card (F11 included). */
export function demoPlan(planId: string): { plan: PlansRow; corpus: PlansRow[] } {
  const fixture = GOLDEN_FIXTURES.find((f) => f.plan_id === planId)
  if (!fixture) throw new Error(`no golden fixture for ${planId}`)
  const corpus = buildDemoCorpus([fixture])
  const plan = corpus.find((r) => r.item_id === planId && r.record_type === 'plan')
  if (!plan) throw new Error(`no demo plan ${planId}`)
  return { plan, corpus }
}
