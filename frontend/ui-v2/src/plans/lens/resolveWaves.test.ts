import { describe, expect, it } from 'vitest'
import { GOLDEN_FIXTURES, F2, F3, F4, F5, F6, F7, F8, F10, F11, kids, task, type FixtureRow, type GoldenFixture } from './__fixtures__'
import { MAX_DESCENDANT_DEPTH, WAVE_RESOLVER_VERSION, parseWaveToken, resolveWaves, type PlacementReason, type ResolvedPlan } from './resolveWaves'

const run = (f: GoldenFixture, rows: readonly FixtureRow[] = f.rows): ResolvedPlan => resolveWaves({ objectives_set: f.objectives }, rows)

/** The reason each id of a fixture should carry, written from the fixture's own lists, never from the resolver. */
const expectedReasons = (f: GoldenFixture): Record<string, PlacementReason> => {
  const out: Record<string, PlacementReason> = {}
  for (const w of f.expected.waves) {
    for (const m of w.members) out[m] = f.expected.byTitle.includes(m) ? 'title' : f.expected.byLabel.includes(m) ? 'label' : 'parent'
  }
  for (const u of f.expected.unassigned) out[u] = 'unassigned'
  return out
}

const shape = (r: ResolvedPlan) =>
  r.waves.map(({ series, number, label, parent_id, placement, members }) => ({ series, number, label, parent_id, placement, members }))

/** Deterministic shuffle so a failure reproduces. */
const shuffled = <T,>(items: readonly T[], seed: number): T[] => {
  const out = [...items]
  let s = seed
  for (let i = out.length - 1; i > 0; i -= 1) {
    s = (s * 1103515245 + 12345) & 0x7fffffff
    const j = s % (i + 1)
    ;[out[i], out[j]] = [out[j] as T, out[i] as T]
  }
  return out
}

const sortedMembers = (r: ResolvedPlan) => r.waves.map((w) => ({ label: w.label, parent_id: w.parent_id, members: [...w.members].sort() }))

describe('WAVE_RESOLVER_VERSION', () => {
  it('is exported, is 1, and is stamped on every result', () => {
    expect(WAVE_RESOLVER_VERSION).toBe(1)
    for (const f of GOLDEN_FIXTURES) expect(run(f).resolver_version, f.name).toBe(WAVE_RESOLVER_VERSION)
  })
})

describe('golden fixtures F1 to F11 (DOC-F3E7C341EB27 section 7)', () => {
  it('has exactly eleven fixtures, F1 to F11, and only F11 is synthetic', () => {
    expect(GOLDEN_FIXTURES.map((f) => f.id)).toEqual(['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11'])
    expect(GOLDEN_FIXTURES.filter((f) => f.synthetic).map((f) => f.id)).toEqual(['F11'])
  })

  describe.each(GOLDEN_FIXTURES.map((f) => [f.name, f] as const))('%s', (_name, f) => {
    it('reproduces the waves, the chips and the Unassigned group', () => {
      const r = run(f)
      expect(shape(r)).toEqual(f.expected.waves)
      expect(r.chips).toEqual(f.expected.chips)
      expect(r.unassigned).toEqual(f.expected.unassigned)
      expect(r.missing).toEqual([])
    })

    it('reports the placement reason of every member and every unassigned row', () => {
      expect(run(f).placements).toEqual(expectedReasons(f))
    })

    it('gives every wave a distinct key', () => {
      const keys = run(f).waves.map((w) => w.key)
      expect(new Set(keys).size).toBe(keys.length)
    })

    it('places each row once', () => {
      const r = run(f)
      const all = [...r.waves.flatMap((w) => w.members), ...r.unassigned, ...r.chips]
      expect(new Set(all).size).toBe(all.length)
    })

    // D-20: a row reaches a wave by label, parent, title or Unassigned, never by where it sits.
    it('does not depend on the order of the corpus rows (membership, reasons and wave order)', () => {
      const base = run(f)
      for (const seed of [1, 2, 3, 4, 5]) {
        const r = run(f, shuffled(f.rows, seed))
        expect(sortedMembers(r), `${f.id} rows shuffled with seed ${seed}`).toEqual(sortedMembers(base))
        expect(r.placements).toEqual(base.placements)
        expect(r.unassigned).toEqual(base.unassigned)
        expect(r.chips).toEqual(base.chips)
      }
      expect(sortedMembers(run(f, [...f.rows].reverse()))).toEqual(sortedMembers(base))
    })

    it('never attaches an unnumbered objective to a neighbour, wherever it is inserted', () => {
      const base = run(f)
      const intruder = task('ZZZ-TSK-INTRUDER', 'Fix an unrelated thing')
      for (let at = 0; at <= f.objectives.length; at += 1) {
        const objectives = [...f.objectives.slice(0, at), intruder.item_id, ...f.objectives.slice(at)]
        const r = resolveWaves({ objectives_set: objectives }, [...f.rows, intruder])
        expect(r.placements[intruder.item_id], `${f.id} intruder inserted at ${at}`).toBe('unassigned')
        expect(r.waves.some((w) => w.members.includes(intruder.item_id))).toBe(false)
        expect(shape(r)).toEqual(shape(base))
        expect(r.unassigned.filter((id) => id !== intruder.item_id)).toEqual(base.unassigned)
      }
    })

    it('ignores the title, label and stale subtask_ids of descendants (parent pointers decide)', () => {
      const base = run(f)
      const memberIds = new Set(f.expected.waves.flatMap((w) => w.members).filter((m) => !f.expected.byTitle.includes(m) && !f.expected.byLabel.includes(m)))
      const poisoned = f.rows.map((row): FixtureRow =>
        memberIds.has(row.item_id) ? { ...row, title: 'W9 V9 wave 9 [Wave 9]', wave_label: 'POISON', subtask_ids: ['ENC-TSK-NOWHERE'] } : { ...row, subtask_ids: undefined },
      )
      const r = run(f, poisoned)
      expect(shape(r)).toEqual(shape(base))
      expect(r.placements).toEqual(base.placements)
    })

    it('ignores rows that are not in the plan: other plans, issues pointing at a wave parent, orphans', () => {
      const parentId = f.expected.waves.find((w) => w.parent_id)?.parent_id
      const noise: FixtureRow[] = [
        task('NOISE-TSK-001', 'W1 an unrelated plan'),
        task('NOISE-TSK-002', 'orphan', { parent: 'NOISE-TSK-NOPE' }),
        { item_id: 'NOISE-ISS-001', record_type: 'issue', title: 'W1 an issue', parent: parentId ?? 'NOISE-TSK-001' },
        { item_id: 'NOISE-PLN-001', record_type: 'plan', title: 'a plan' },
      ]
      expect(run(f, [...f.rows, ...noise])).toEqual(run(f))
    })
  })
})

describe('the assertions that matter, one per fixture trap', () => {
  const planOf = (f: GoldenFixture) => run(f)
  const waveOf = (f: GoldenFixture, memberId: string) => planOf(f).waves.find((w) => w.members.includes(memberId))

  it('F2: V1:/V2:/V3: descendant titles produce no waves of their own (exactly six waves)', () => {
    const r = planOf(F2)
    expect(r.waves).toHaveLength(6)
    expect(r.waves.map((w) => w.series)).toEqual(['W', 'W', 'W', 'W', 'W', 'W'])
    expect(waveOf(F2, 'HFY-TSK-392')?.label).toBe('W1')
    expect(waveOf(F2, 'HFY-TSK-394')?.label).toBe('W2')
  })

  it('F3: the leading 4.1 yields no wave, and the three DVP-* objectives resolve inside an ENC plan', () => {
    const r = planOf(F3)
    expect(r.waves.map((w) => w.label)).toEqual(['W0', 'W1', 'W2', 'W3', 'W4'])
    for (const id of ['DVP-TSK-B87', 'DVP-TSK-B88', 'DVP-TSK-B89']) {
      expect(waveOf(F3, id)?.label).toBe('W0')
      expect(r.placements[id]).toBe('title')
    }
  })

  it('F3: W0 is a parent wave that also holds three title-placed members, and says so per member', () => {
    const r = planOf(F3)
    const w0 = r.waves[0]
    expect(w0?.placement).toBe('parent')
    expect(w0?.parent_id).toBe('ENC-TSK-R80')
    expect(w0?.members.map((m) => r.placements[m])).toEqual(['parent', 'parent', 'title', 'title', 'title'])
  })

  it('F3: the W1 parent narrates W0 in its title; only the first token counts (spec 3.2)', () => {
    const r = planOf(F3)
    expect(r.waves.find((w) => w.parent_id === 'ENC-TSK-R81')?.number).toBe(1)
  })

  it('F4: v1.1 yields no wave, and ENC-TSK-S77 is in W6 by parent', () => {
    const r = planOf(F4)
    expect(r.waves.map((w) => w.number)).toEqual([0, 1, 2, 3, 4, 5, 6])
    expect(waveOf(F4, 'ENC-TSK-S77')?.label).toBe('W6')
    expect(r.placements['ENC-TSK-S77']).toBe('parent')
  })

  it('F4: removing ENC-TSK-S77\'s title entirely does not change its placement', () => {
    const rows = F4.rows.map((row): FixtureRow => (row.item_id === 'ENC-TSK-S77' ? { ...row, title: '' } : row))
    const r = run(F4, rows)
    expect(r.waves.find((w) => w.members.includes('ENC-TSK-S77'))?.label).toBe('W6')
    expect(r.placements['ENC-TSK-S77']).toBe('parent')
  })

  it('F5: DVP-TSK-974 is in W2 because its parent is W2, against its title (W3) and DVP-TSK-962\'s subtask_ids (W3)', () => {
    const r = planOf(F5)
    const row962 = F5.rows.find((x) => x.item_id === 'DVP-TSK-962')
    const row974 = F5.rows.find((x) => x.item_id === 'DVP-TSK-974')
    // The fixture really carries the two disagreeing sources; otherwise the assertion below proves nothing.
    expect(row962?.subtask_ids).toContain('DVP-TSK-974')
    expect(row974?.title).toMatch(/^E4-W3\.1/)
    expect(waveOf(F5, 'DVP-TSK-974')?.parent_id).toBe('DVP-TSK-961')
    expect(waveOf(F5, 'DVP-TSK-974')?.label).toBe('W2')
    expect(r.placements['DVP-TSK-974']).toBe('parent')
    expect(r.waves.find((w) => w.parent_id === 'DVP-TSK-962')?.members).not.toContain('DVP-TSK-974')
  })

  it('F6: ordering is by number (W4 before W5 though S87 precedes S85), S83 joins the wave S82 founded, S88 is never attached to S85', () => {
    const r = planOf(F6)
    expect(r.waves.map((w) => w.label)).toEqual(['W1', 'W2', 'W3', 'W4', 'W5'])
    expect(F6.objectives.indexOf('ENC-TSK-S87')).toBeLessThan(F6.objectives.indexOf('ENC-TSK-S85'))
    expect(r.waves.filter((w) => w.number === 2)).toHaveLength(1)
    expect(waveOf(F6, 'ENC-TSK-S83')?.members).toEqual(['ENC-TSK-S82', 'ENC-TSK-S83'])
    expect(waveOf(F6, 'ENC-TSK-S88')).toBeUndefined()
    expect(waveOf(F6, 'ENC-TSK-S85')?.members).toEqual(['ENC-TSK-S85'])
    expect(r.unassigned).toEqual(['ENC-TSK-S88'])
    expect(r.placements['ENC-TSK-S88']).toBe('unassigned')
  })

  it('F7 (D-20): W3 holds FIN-TSK-266 alone and the four fix tasks are Unassigned, the group drawn last', () => {
    const r = planOf(F7)
    expect(r.waves.at(-1)?.members).toEqual(['FIN-TSK-266'])
    expect(r.unassigned).toEqual(['FIN-TSK-267', 'FIN-TSK-268', 'FIN-TSK-269', 'FIN-TSK-270'])
    for (const id of r.unassigned) expect(r.placements[id]).toBe('unassigned')
    expect(F7.objectives.indexOf('FIN-TSK-267')).toBe(F7.objectives.indexOf('FIN-TSK-266') + 1)
  })

  it('F8: H wave 0 and F wave 0 are two waves, and two series fall back to objective order', () => {
    const r = planOf(F8)
    expect(r.waves.map((w) => w.label)).toEqual(['H0', 'F0', 'H1', 'F1', 'H2', 'F2', 'H3', 'F3'])
    expect(r.waves.filter((w) => w.number === 0).map((w) => w.series)).toEqual(['H', 'F'])
    expect(r.chips).toEqual(['FIN-FTR-027', 'FIN-FTR-028'])
  })

  it('F10: V1 and W3 are not compared across series, and INT-TSK-641-0A (titled W1.1) is a member of V1', () => {
    const r = planOf(F10)
    expect(r.waves.map((w) => w.label)).toEqual(['V1', 'V2', 'W3', 'W4', 'W5', 'W6', 'W7'])
    expect(waveOf(F10, 'INT-TSK-641-0A')?.label).toBe('V1')
    expect(r.placements['INT-TSK-641-0A']).toBe('parent')
    const w7 = r.waves.at(-1)
    expect([w7?.placement, w7?.parent_id]).toEqual(['title', null])
    expect(r.waves.filter((w) => w.placement === 'parent')).toHaveLength(6)
  })

  it('F11: step 1 beats step 3, a labelled objective is never Unassigned, and labels are opaque', () => {
    const r = planOf(F11)
    expect(waveOf(F11, 'ENC-TSK-S82')?.label).toBe('W1')
    expect(waveOf(F11, 'ENC-TSK-S88')?.label).toBe('W2')
    expect(r.unassigned).toEqual([])
    expect(r.placements).toEqual({ 'ENC-TSK-S81': 'label', 'ENC-TSK-S82': 'label', 'ENC-TSK-S84': 'label', 'ENC-TSK-S88': 'label' })
    for (const w of r.waves) expect([w.series, w.number, w.placement]).toEqual([null, null, 'label'])
  })

  it('F11: removing the labels returns F6-style title placement, proving the label was what decided', () => {
    const rows = F11.rows.map((row): FixtureRow => ({ ...row, wave_label: null }))
    const r = run(F11, rows)
    expect(r.waves.map((w) => w.label)).toEqual(['W1', 'W2', 'W3'])
    expect(r.unassigned).toEqual(['ENC-TSK-S88'])
  })
})

describe('parseWaveToken: the title grammar and its traps (spec section 3.3, one assertion per real title)', () => {
  const cases: ReadonlyArray<readonly [title: string, expected: { series: string; number: number } | null, why: string]> = [
    ['4.1 W0 -- Truth and foundations', { series: 'W', number: 0 }, 'the leading 4.1 has no letter marker'],
    ['DS v1.1 W1.1 Three-tier tokens', { series: 'W', number: 1 }, 'form A is case-sensitive: lowercase v1.1 is a version'],
    ['E4-W0 io decisions', { series: 'W', number: 0 }, 'a hyphen is a legal preceding character, and E4 is neither W nor V'],
    ['INT-PLN-033 W0 contract', { series: 'W', number: 0 }, 'record ids carry digits but no bare W or V marker'],
    ['io-graph FalkorDB V1 -- 4.x baseline freeze', { series: 'V', number: 1 }, 'uppercase V followed by a digit; 4.x has no digit after a marker'],
    ['R5.5: loan statement lines are held by rule', null, 'R is not a marker, so the row is Unassigned'],
    ['io-identified payees: ACFU Visa, Chase Auto Loan', null, 'the V of Visa is not followed by a digit'],
    ['[Wave 1] Foundations', { series: 'W', number: 1 }, 'form B with no series letter'],
    ['P-HFY-MEDIA W1 [wave-1] Ground truth', { series: 'W', number: 1 }, 'form A matches first and the [wave-1] slug agrees'],
    ['H wave 0 -- Housing contract', { series: 'H', number: 0 }, 'form B with a series letter'],
  ]
  it.each(cases)('%s', (title, expected, why) => {
    const token = parseWaveToken(title)
    expect(token === null ? null : { series: token.series, number: token.number }, why).toEqual(expected)
  })

  it('first match wins: a wave parent that narrates its dependency on W0 is wave 1 (spec 3.2)', () => {
    const t = '4.1 W1 -- Signals, identity, cockpit and retrieval first layer (wave parent; children parallel, depend on W0 only)'
    expect(parseWaveToken(t)).toMatchObject({ series: 'W', number: 1 })
  })

  it('first match wins across the two forms, in reading order', () => {
    expect(parseWaveToken('[wave-2] then W5')).toMatchObject({ number: 2 })
    expect(parseWaveToken('then W5 and [wave-2]')).toMatchObject({ number: 5 })
  })

  it('finds the token wherever it sits: after a gate word and inside a trailing parenthesis (F9)', () => {
    expect(parseWaveToken('INT-PLN-033 Gate W1: schema review')).toMatchObject({ series: 'W', number: 1 })
    expect(parseWaveToken('Coach feed read path: cursor and paging (INT-PLN-033 W1 backend)')).toMatchObject({ series: 'W', number: 1 })
  })

  it('reads the subordinal after a dot or a hyphen, and it never creates a wave', () => {
    expect(parseWaveToken('W0.12 x')).toMatchObject({ number: 0, subordinal: '12' })
    expect(parseWaveToken('4.1 W2.1b x')).toMatchObject({ number: 2, subordinal: '1b' })
    expect(parseWaveToken('W2-A x')).toMatchObject({ number: 2, subordinal: 'A' })
    expect(parseWaveToken('W1 -- x')?.subordinal).toBeNull()
    expect(parseWaveToken('W1. x')?.subordinal).toBeNull()
  })

  it('returns null for an empty or absent title', () => {
    expect(parseWaveToken('')).toBeNull()
    expect(parseWaveToken(null)).toBeNull()
    expect(parseWaveToken(undefined)).toBeNull()
  })

  it('a bare word `wave` with no digits is not a token', () => {
    expect(parseWaveToken('the wave parent; children parallel')).toBeNull()
  })
})

describe('resolveWaves: behaviours the fixtures do not reach', () => {
  const plan = (...objectives: string[]) => ({ objectives_set: objectives })

  it('an empty or absent objectives_set yields no waves and no chips (spec section 9)', () => {
    expect(resolveWaves({ objectives_set: [] }, [])).toEqual({
      resolver_version: 1, waves: [], chips: [], unassigned: [], placements: {}, missing: [],
    })
    expect(resolveWaves({}, [task('A', 'W1')]).waves).toEqual([])
    expect(resolveWaves({ objectives_set: null }, []).waves).toEqual([])
  })

  it('walks at most three levels below an objective', () => {
    const rows = [
      task('P', 'W1'),
      ...kids('P', [['L1', 'a']]),
      ...kids('L1', [['L2', 'b']]),
      ...kids('L2', [['L3', 'c']]),
      ...kids('L3', [['L4', 'd']]),
    ]
    expect(MAX_DESCENDANT_DEPTH).toBe(3)
    expect(resolveWaves(plan('P'), rows).waves[0]?.members).toEqual(['L1', 'L2', 'L3'])
  })

  it('terminates on a parent cycle and never lists a row twice', () => {
    const cycle = [task('P', 'W1', { parent: 'C' }), task('C', 'c', { parent: 'P' }), task('D', 'd', { parent: 'D' }), task('E', 'e', { parent: 'C' })]
    expect(resolveWaves(plan('P'), cycle).waves[0]?.members).toEqual(['C', 'E'])
    // A row that is its own parent is not a child of anything, so the objective stays childless (step 3).
    const selfParent = [task('P', 'W1', { parent: 'P' }), task('S', 's', { parent: 'S' })]
    expect(resolveWaves(plan('P'), selfParent).waves[0]).toMatchObject({ parent_id: null, members: ['P'], placement: 'title' })
  })

  it('orders siblings by created_at when the rows carry it, otherwise by corpus order', () => {
    const rows = [
      task('P', 'W1'),
      task('LATE', 'x', { parent: 'P', created_at: '2026-11-19T10:00:00Z' }),
      task('EARLY', 'y', { parent: 'P', created_at: '2026-11-19T08:00:00Z' }),
      task('NODATE', 'z', { parent: 'P' }),
    ]
    expect(resolveWaves(plan('P'), rows).waves[0]?.members).toEqual(['EARLY', 'LATE', 'NODATE'])
  })

  it('sorts a parentless wave by subordinal when every member has one (R-1), numerically then by letters', () => {
    const rows = [task('A', 'W2.10 x'), task('B', 'W2.9 y'), task('C', 'W2.1b z'), task('D', 'W2.1 w')]
    expect(resolveWaves(plan('A', 'B', 'C', 'D'), rows).waves[0]?.members).toEqual(['D', 'C', 'B', 'A'])
  })

  it('never reads a descendant\'s title, not even to order it: a wave parent\'s tree stays in corpus order (spec 3.4, 4.2)', () => {
    const rows = [task('P', 'W1'), ...kids('P', [['B', 'W1.2 second'], ['A', 'W1.1 first']])]
    expect(resolveWaves(plan('P'), rows).waves[0]?.members).toEqual(['B', 'A'])
  })

  it('keeps objective order when any member lacks a subordinal', () => {
    const rows = [task('A', 'W2.9 x'), task('B', 'W2 y'), task('C', 'W2.1 z')]
    expect(resolveWaves(plan('A', 'B', 'C'), rows).waves[0]?.members).toEqual(['A', 'B', 'C'])
  })

  it('step 3 joins the nearest PRECEDING wave of the same series and number, and founds one when there is none', () => {
    const rows = [
      task('EARLY', 'W2.1 before any wave 2'),
      task('P', 'W2 -- parent'),
      ...kids('P', [['P1', 'child']]),
      task('LATE', 'W2.2 after the parent'),
    ]
    const r = resolveWaves(plan('EARLY', 'P', 'LATE'), rows)
    expect(r.waves.map((w) => [w.key, w.parent_id, w.placement, w.members])).toEqual([
      ['W2', null, 'title', ['EARLY']],
      ['W2#2', 'P', 'parent', ['P1', 'LATE']],
    ])
  })

  it('two series fall to objective order even where a numeric sort would reorder them', () => {
    const rows = [
      task('H1', 'H wave 1'), ...kids('H1', [['H1a', 'x']]),
      task('F0', 'F wave 0'), ...kids('F0', [['F0a', 'x']]),
      task('H0', 'H wave 0'), ...kids('H0', [['H0a', 'x']]),
    ]
    expect(resolveWaves(plan('H1', 'F0', 'H0'), rows).waves.map((w) => w.label)).toEqual(['H1', 'F0', 'H0'])
  })

  it('one series sorts by number whatever the objective order, with objective order breaking ties', () => {
    const rows = [task('A', 'W3'), task('B', 'W1'), task('C', 'W2'), task('D', 'W1.2')]
    const r = resolveWaves(plan('A', 'B', 'C', 'D'), rows)
    expect(r.waves.map((w) => [w.label, w.members])).toEqual([['W1', ['B', 'D']], ['W2', ['C']], ['W3', ['A']]])
  })

  it('a labelled wave among numbered ones forces objective order', () => {
    const rows = [task('A', 'W3'), task('B', 'x', { wave_label: 'Spike' }), task('C', 'W1')]
    expect(resolveWaves(plan('A', 'B', 'C'), rows).waves.map((w) => w.label)).toEqual(['W3', 'Spike', 'W1'])
  })

  it('a series mismatch does not join: V1 and W1 are different waves', () => {
    const r = resolveWaves(plan('A', 'B'), [task('A', 'V1 x'), task('B', 'W1 y')])
    expect(r.waves.map((w) => w.label)).toEqual(['V1', 'W1'])
  })

  it('an unnumbered wave parent still forms a wave, labelled by its own id, and forces objective order', () => {
    const rows = [task('P', 'Housing cleanup'), ...kids('P', [['P1', 'x']]), task('Q', 'W0 Truth'), ...kids('Q', [['Q1', 'y']])]
    const r = resolveWaves(plan('P', 'Q'), rows)
    expect(r.waves.map((w) => [w.label, w.series, w.number, w.placement])).toEqual([
      ['P', null, null, 'parent'],
      ['W0', 'W', 0, 'parent'],
    ])
  })

  it('a labelled objective with children is that wave\'s parent, and its descendants are members by parent', () => {
    const rows = [task('P', 'whatever', { wave_label: 'Alpha' }), ...kids('P', [['P1', 'x']]), task('Q', 'W9', { wave_label: 'Alpha' })]
    const r = resolveWaves(plan('P', 'Q'), rows)
    expect(r.waves).toHaveLength(1)
    expect(r.waves[0]).toMatchObject({ label: 'Alpha', parent_id: 'P', placement: 'label', members: ['P1', 'Q'] })
    expect(r.placements).toEqual({ P1: 'parent', Q: 'label' })
  })

  it('labels are byte-equal opaque strings: W1 and w1 and "W1 " are three waves', () => {
    const rows = [task('A', 'x', { wave_label: 'W1' }), task('B', 'x', { wave_label: 'w1' }), task('C', 'x', { wave_label: 'W1 ' })]
    expect(resolveWaves(plan('A', 'B', 'C'), rows).waves.map((w) => w.label)).toEqual(['W1', 'w1', 'W1 '])
  })

  it('non-task objectives are chips whatever they carry, and are never placed', () => {
    const rows: FixtureRow[] = [
      { item_id: 'F', record_type: 'feature', title: 'W1 a feature', wave_label: 'W1' },
      { item_id: 'I', record_type: 'issue', title: 'an issue' },
      task('T', 'W1 x'),
    ]
    const r = resolveWaves(plan('F', 'I', 'T'), rows)
    expect(r.chips).toEqual(['F', 'I'])
    expect(r.waves.map((w) => w.members)).toEqual([['T']])
    expect(r.placements).toEqual({ T: 'title' })
  })

  it('an objective with no row in the corpus is reported as missing, never placed or guessed', () => {
    const r = resolveWaves(plan('GONE', 'T'), [task('T', 'W1 x')])
    expect(r.missing).toEqual(['GONE'])
    expect(r.placements).toEqual({ T: 'title' })
    expect(r.unassigned).toEqual([])
  })

  it('a duplicated objective is resolved once', () => {
    const r = resolveWaves(plan('T', 'T'), [task('T', 'W1 x')])
    expect(r.waves.map((w) => w.members)).toEqual([['T']])
  })

  it('does not descend into another objective of the same plan: that objective is placed by its own rule', () => {
    const rows = [task('A', 'W1'), task('B', 'W2', { parent: 'A' }), ...kids('B', [['B1', 'x']])]
    const r = resolveWaves(plan('A', 'B'), rows)
    expect(r.waves.map((w) => [w.label, w.parent_id, w.members])).toEqual([
      ['W1', 'A', []],
      ['W2', 'B', ['B1']],
    ])
  })

  it('does not mutate its inputs', () => {
    const rows = F3.rows.map((x) => ({ ...x }))
    const objectives = [...F3.objectives]
    const before = JSON.stringify([rows, objectives])
    resolveWaves({ objectives_set: objectives }, rows)
    expect(JSON.stringify([rows, objectives])).toBe(before)
  })

  it('is deterministic: the same input gives a deeply equal result', () => {
    for (const f of GOLDEN_FIXTURES) expect(run(f)).toEqual(run(f))
  })
})
