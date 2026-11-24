import { kids, task, type GoldenFixture } from './builders'

/**
 * F4, ENC-PLN-106: shape 1, the lowercase-v trap (`DS v1.1 W1.1`), and a descendant whose title happens to agree with
 * its parent. ENC-TSK-S77 is titled `DS v1.1 W6.3` and parented to ENC-TSK-S65 (W6): a member of W6 by parent, and the
 * agreement with its title is a coincidence the fixture must not rely on.
 */
export const F4: GoldenFixture = {
  id: 'F4',
  plan_id: 'ENC-PLN-106',
  name: 'F4 ENC-PLN-106 lowercase-v trap, descendant whose title agrees',
  shape: '1',
  synthetic: false,
  objectives: ['ENC-TSK-S59', 'ENC-TSK-S60', 'ENC-TSK-S61', 'ENC-TSK-S62', 'ENC-TSK-S63', 'ENC-TSK-S64', 'ENC-TSK-S65'],
  rows: [
    task('ENC-TSK-S59', 'DS v1.1 W0 -- Baseline and decisions'),
    ...kids('ENC-TSK-S59', [['ENC-TSK-S59-0A', 'Import the design system']]),
    task('ENC-TSK-S60', 'DS v1.1 W1 -- Three-tier tokens'),
    ...kids('ENC-TSK-S60', [['ENC-TSK-S60-0A', 'Role tokens'], ['ENC-TSK-S60-0B', 'Status lookup']]),
    task('ENC-TSK-S61', 'DS v1.1 W2 -- Status pill'),
    ...kids('ENC-TSK-S61', [['ENC-TSK-S61-0A', 'Status pill']]),
    task('ENC-TSK-S62', 'DS v1.1 W3 -- Pill family'),
    ...kids('ENC-TSK-S62', [['ENC-TSK-S62-0A', 'Pill family'], ['ENC-TSK-S62-0B', 'Meters, diff, alerts']]),
    task('ENC-TSK-S63', 'DS v1.1 W4 -- Record card'),
    ...kids('ENC-TSK-S63', [['ENC-TSK-S63-0A', 'Record card'], ['ENC-TSK-S63-0B', 'Detail surfaces'], ['ENC-TSK-S63-0C', 'Reskin components']]),
    task('ENC-TSK-S64', 'DS v1.1 W5 -- Adherence'),
    ...kids('ENC-TSK-S64', [['ENC-TSK-S64-0A', 'Adherence lint'], ['ENC-TSK-S64-0B', 'Lint ratchet']]),
    task('ENC-TSK-S65', 'DS v1.1 W6 -- Exit'),
    ...kids('ENC-TSK-S65', [['ENC-TSK-S65-0A', 'Production deploy']]),
    task('ENC-TSK-S77', 'DS v1.1 W6.3 Exit report', { parent: 'ENC-TSK-S65' }),
  ],
  expected: {
    waves: [
      { series: 'W', number: 0, label: 'W0', parent_id: 'ENC-TSK-S59', placement: 'parent', members: ['ENC-TSK-S59-0A'] },
      { series: 'W', number: 1, label: 'W1', parent_id: 'ENC-TSK-S60', placement: 'parent', members: ['ENC-TSK-S60-0A', 'ENC-TSK-S60-0B'] },
      { series: 'W', number: 2, label: 'W2', parent_id: 'ENC-TSK-S61', placement: 'parent', members: ['ENC-TSK-S61-0A'] },
      { series: 'W', number: 3, label: 'W3', parent_id: 'ENC-TSK-S62', placement: 'parent', members: ['ENC-TSK-S62-0A', 'ENC-TSK-S62-0B'] },
      { series: 'W', number: 4, label: 'W4', parent_id: 'ENC-TSK-S63', placement: 'parent', members: ['ENC-TSK-S63-0A', 'ENC-TSK-S63-0B', 'ENC-TSK-S63-0C'] },
      { series: 'W', number: 5, label: 'W5', parent_id: 'ENC-TSK-S64', placement: 'parent', members: ['ENC-TSK-S64-0A', 'ENC-TSK-S64-0B'] },
      { series: 'W', number: 6, label: 'W6', parent_id: 'ENC-TSK-S65', placement: 'parent', members: ['ENC-TSK-S65-0A', 'ENC-TSK-S77'] },
    ],
    chips: [],
    unassigned: [],
    byTitle: [],
    byLabel: [],
  },
}
