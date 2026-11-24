import { task, type GoldenFixture } from './builders'

/**
 * F7, FIN-PLN-009: shape 3 and ruling D-20. Four fix tasks (267 to 270) were appended after `W3-A` with no wave number.
 * They form the Unassigned group; W3 holds FIN-TSK-266 alone, so the page reads it as todo and not as active. This is
 * acceptance criterion 3 of ENC-TSK-S95-0C verbatim.
 */
export const F7: GoldenFixture = {
  id: 'F7',
  plan_id: 'FIN-PLN-009',
  name: 'F7 FIN-PLN-009 ruling D-20, four unnumbered fix tasks after W3-A',
  shape: '3',
  synthetic: false,
  objectives: [
    'FIN-TSK-256', 'FIN-TSK-257', 'FIN-TSK-258',
    'FIN-TSK-259', 'FIN-TSK-260', 'FIN-TSK-261',
    'FIN-TSK-262', 'FIN-TSK-263', 'FIN-TSK-264', 'FIN-TSK-265',
    'FIN-TSK-266',
    'FIN-TSK-267', 'FIN-TSK-268', 'FIN-TSK-269', 'FIN-TSK-270',
  ],
  rows: [
    task('FIN-TSK-256', 'W0-A Statement line model'),
    task('FIN-TSK-257', 'W0-B Account model'),
    task('FIN-TSK-258', 'W0-C Category model'),
    task('FIN-TSK-259', 'W1-A Capture statement lines'),
    task('FIN-TSK-260', 'W1-B Reconcile statement lines'),
    task('FIN-TSK-261', 'W1-C Promote statement lines'),
    task('FIN-TSK-262', 'W2-A Loan statement rules'),
    task('FIN-TSK-263', 'W2-B Payee patterns'),
    task('FIN-TSK-264', 'W2-C Exceptions report'),
    task('FIN-TSK-265', 'W2-D Held lines'),
    task('FIN-TSK-266', 'W3-A Exit report'),
    task('FIN-TSK-267', 'Fix payee pattern for a card refund'),
    task('FIN-TSK-268', 'Fix duplicate statement import'),
    task('FIN-TSK-269', 'Fix category drift after retype'),
    task('FIN-TSK-270', 'Fix held-line count on the summary'),
  ],
  expected: {
    waves: [
      { series: 'W', number: 0, label: 'W0', parent_id: null, placement: 'title', members: ['FIN-TSK-256', 'FIN-TSK-257', 'FIN-TSK-258'] },
      { series: 'W', number: 1, label: 'W1', parent_id: null, placement: 'title', members: ['FIN-TSK-259', 'FIN-TSK-260', 'FIN-TSK-261'] },
      { series: 'W', number: 2, label: 'W2', parent_id: null, placement: 'title', members: ['FIN-TSK-262', 'FIN-TSK-263', 'FIN-TSK-264', 'FIN-TSK-265'] },
      { series: 'W', number: 3, label: 'W3', parent_id: null, placement: 'title', members: ['FIN-TSK-266'] },
    ],
    chips: [],
    unassigned: ['FIN-TSK-267', 'FIN-TSK-268', 'FIN-TSK-269', 'FIN-TSK-270'],
    byTitle: [
      'FIN-TSK-256', 'FIN-TSK-257', 'FIN-TSK-258', 'FIN-TSK-259', 'FIN-TSK-260', 'FIN-TSK-261',
      'FIN-TSK-262', 'FIN-TSK-263', 'FIN-TSK-264', 'FIN-TSK-265', 'FIN-TSK-266',
    ],
    byLabel: [],
  },
}
