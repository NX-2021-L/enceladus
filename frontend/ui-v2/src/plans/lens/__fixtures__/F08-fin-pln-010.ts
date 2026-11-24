import { feature, kids, task, type GoldenFixture } from './builders'

/**
 * F8, FIN-PLN-010: shapes 4 and 5. Two feature objectives become chips. Series H and F each hold wave numbers 0 to 3, so
 * `H wave 0` and `F wave 0` are two distinct waves, and because two series are present the order falls to objective
 * order: a numeric sort that collapsed the series would be caught here.
 */
export const F8: GoldenFixture = {
  id: 'F8',
  plan_id: 'FIN-PLN-010',
  name: 'F8 FIN-PLN-010 features mixed in, two series reusing numbers',
  shape: '4, 5',
  synthetic: false,
  objectives: [
    'FIN-FTR-027',
    'FIN-FTR-028',
    'FIN-TSK-280', 'FIN-TSK-284', 'FIN-TSK-281', 'FIN-TSK-285', 'FIN-TSK-282', 'FIN-TSK-286', 'FIN-TSK-283', 'FIN-TSK-287',
  ],
  rows: [
    feature('FIN-FTR-027', 'Housing agreements'),
    feature('FIN-FTR-028', 'Account terms'),
    task('FIN-TSK-280', 'H wave 0 -- Housing contract'),
    ...kids('FIN-TSK-280', [['FIN-TSK-280-0A', 'Agreement model']]),
    task('FIN-TSK-284', 'F wave 0 -- Account terms contract'),
    ...kids('FIN-TSK-284', [['FIN-TSK-284-0A', 'Term model']]),
    task('FIN-TSK-281', 'H wave 1 -- Housing capture'),
    ...kids('FIN-TSK-281', [['FIN-TSK-281-0A', 'Agreement capture']]),
    task('FIN-TSK-285', 'F wave 1 -- Account terms capture'),
    ...kids('FIN-TSK-285', [['FIN-TSK-285-0A', 'Term capture']]),
    task('FIN-TSK-282', 'H wave 2 -- Housing reports'),
    ...kids('FIN-TSK-282', [['FIN-TSK-282-0A', 'Rent roll']]),
    task('FIN-TSK-286', 'F wave 2 -- Account terms reports'),
    ...kids('FIN-TSK-286', [['FIN-TSK-286-0A', 'Fee report']]),
    task('FIN-TSK-283', 'H wave 3 -- Housing exit'),
    ...kids('FIN-TSK-283', [['FIN-TSK-283-0A', 'Housing close-out']]),
    task('FIN-TSK-287', 'F wave 3 -- Account terms exit'),
    ...kids('FIN-TSK-287', [['FIN-TSK-287-0A', 'Terms close-out']]),
  ],
  expected: {
    waves: [
      { series: 'H', number: 0, label: 'H0', parent_id: 'FIN-TSK-280', placement: 'parent', members: ['FIN-TSK-280-0A'] },
      { series: 'F', number: 0, label: 'F0', parent_id: 'FIN-TSK-284', placement: 'parent', members: ['FIN-TSK-284-0A'] },
      { series: 'H', number: 1, label: 'H1', parent_id: 'FIN-TSK-281', placement: 'parent', members: ['FIN-TSK-281-0A'] },
      { series: 'F', number: 1, label: 'F1', parent_id: 'FIN-TSK-285', placement: 'parent', members: ['FIN-TSK-285-0A'] },
      { series: 'H', number: 2, label: 'H2', parent_id: 'FIN-TSK-282', placement: 'parent', members: ['FIN-TSK-282-0A'] },
      { series: 'F', number: 2, label: 'F2', parent_id: 'FIN-TSK-286', placement: 'parent', members: ['FIN-TSK-286-0A'] },
      { series: 'H', number: 3, label: 'H3', parent_id: 'FIN-TSK-283', placement: 'parent', members: ['FIN-TSK-283-0A'] },
      { series: 'F', number: 3, label: 'F3', parent_id: 'FIN-TSK-287', placement: 'parent', members: ['FIN-TSK-287-0A'] },
    ],
    chips: ['FIN-FTR-027', 'FIN-FTR-028'],
    unassigned: [],
    byTitle: [],
    byLabel: [],
  },
}
