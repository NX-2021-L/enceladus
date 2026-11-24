import { kids, task, type GoldenFixture } from './builders'

/**
 * F10, INT-PLN-031: shape 7, two label series. Series V holds 1 to 2 and series W holds 3 to 7, so ordering falls to
 * objective order and V1 is never compared numerically with W3. INT-TSK-647 is childless, so step 3 founds W7 (placement
 * `title`). INT-TSK-641-0A is titled `W1.1` but its parent is INT-TSK-648, which is wave V1: it is a member of V1.
 */
export const F10: GoldenFixture = {
  id: 'F10',
  plan_id: 'INT-PLN-031',
  name: 'F10 INT-PLN-031 two label series, W1.1 descendant under V1',
  shape: '7',
  synthetic: false,
  objectives: ['INT-TSK-648', 'INT-TSK-649', 'INT-TSK-643', 'INT-TSK-644', 'INT-TSK-645', 'INT-TSK-646', 'INT-TSK-647'],
  rows: [
    task('INT-TSK-648', 'io-graph FalkorDB V1 -- 4.x baseline freeze'),
    task('INT-TSK-641-0A', 'W1.1 Freeze the 4.x graph baseline', { parent: 'INT-TSK-648' }),
    ...kids('INT-TSK-648', [['INT-TSK-648-0B', 'Baseline export']]),
    task('INT-TSK-649', 'io-graph FalkorDB V2 -- dual write'),
    ...kids('INT-TSK-649', [['INT-TSK-649-0A', 'Dual write adapter']]),
    task('INT-TSK-643', 'W3 Coach read model'),
    ...kids('INT-TSK-643', [['INT-TSK-643-0A', 'Read model schema']]),
    task('INT-TSK-644', 'W4 Coach write model'),
    ...kids('INT-TSK-644', [['INT-TSK-644-0A', 'Write model schema']]),
    task('INT-TSK-645', 'W5 Coach feed'),
    ...kids('INT-TSK-645', [['INT-TSK-645-0A', 'Feed projection']]),
    task('INT-TSK-646', 'W6 Coach UI'),
    ...kids('INT-TSK-646', [['INT-TSK-646-0A', 'Coach card']]),
    task('INT-TSK-647', 'W7 Exit'),
  ],
  expected: {
    waves: [
      { series: 'V', number: 1, label: 'V1', parent_id: 'INT-TSK-648', placement: 'parent', members: ['INT-TSK-641-0A', 'INT-TSK-648-0B'] },
      { series: 'V', number: 2, label: 'V2', parent_id: 'INT-TSK-649', placement: 'parent', members: ['INT-TSK-649-0A'] },
      { series: 'W', number: 3, label: 'W3', parent_id: 'INT-TSK-643', placement: 'parent', members: ['INT-TSK-643-0A'] },
      { series: 'W', number: 4, label: 'W4', parent_id: 'INT-TSK-644', placement: 'parent', members: ['INT-TSK-644-0A'] },
      { series: 'W', number: 5, label: 'W5', parent_id: 'INT-TSK-645', placement: 'parent', members: ['INT-TSK-645-0A'] },
      { series: 'W', number: 6, label: 'W6', parent_id: 'INT-TSK-646', placement: 'parent', members: ['INT-TSK-646-0A'] },
      { series: 'W', number: 7, label: 'W7', parent_id: null, placement: 'title', members: ['INT-TSK-647'] },
    ],
    chips: [],
    unassigned: [],
    byTitle: ['INT-TSK-647'],
    byLabel: [],
  },
}
