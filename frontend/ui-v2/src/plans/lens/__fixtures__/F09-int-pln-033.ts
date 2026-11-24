import { feature, task, type GoldenFixture } from './builders'

/**
 * F9, INT-PLN-033: shapes 3 and 4. The wave token sits at the start of a title, after a gate word, or inside a trailing
 * parenthesis; the digits inside `INT-PLN-033` itself never produce a wave. One feature objective becomes a chip.
 */
export const F9: GoldenFixture = {
  id: 'F9',
  plan_id: 'INT-PLN-033',
  name: 'F9 INT-PLN-033 token mid-title and in a trailing parenthesis',
  shape: '3, 4',
  synthetic: false,
  objectives: [
    'INT-FTR-087',
    'INT-TSK-682', 'INT-TSK-683', 'INT-TSK-684', 'INT-TSK-685', 'INT-TSK-686',
    'INT-TSK-687', 'INT-TSK-688', 'INT-TSK-689',
    'INT-TSK-690', 'INT-TSK-691',
  ],
  rows: [
    feature('INT-FTR-087', 'Coach feed'),
    task('INT-TSK-682', 'INT-PLN-033 W0 contract'),
    task('INT-TSK-683', 'INT-PLN-033 Gate W1: schema review'),
    task('INT-TSK-684', 'Coach feed read path: cursor and paging (INT-PLN-033 W1 backend)'),
    task('INT-TSK-685', 'INT-PLN-033 W1 ingest adapter'),
    task('INT-TSK-686', 'INT-PLN-033 W1 identity map'),
    task('INT-TSK-687', 'INT-PLN-033 W2 coach card'),
    task('INT-TSK-688', 'INT-PLN-033 W2 push channel'),
    task('INT-TSK-689', 'Coach card empty state (INT-PLN-033 W2 frontend)'),
    task('INT-TSK-690', 'INT-PLN-033 W3 acceptance'),
    task('INT-TSK-691', 'INT-PLN-033 W3 exit'),
  ],
  expected: {
    waves: [
      { series: 'W', number: 0, label: 'W0', parent_id: null, placement: 'title', members: ['INT-TSK-682'] },
      { series: 'W', number: 1, label: 'W1', parent_id: null, placement: 'title', members: ['INT-TSK-683', 'INT-TSK-684', 'INT-TSK-685', 'INT-TSK-686'] },
      { series: 'W', number: 2, label: 'W2', parent_id: null, placement: 'title', members: ['INT-TSK-687', 'INT-TSK-688', 'INT-TSK-689'] },
      { series: 'W', number: 3, label: 'W3', parent_id: null, placement: 'title', members: ['INT-TSK-690', 'INT-TSK-691'] },
    ],
    chips: ['INT-FTR-087'],
    unassigned: [],
    byTitle: [
      'INT-TSK-682', 'INT-TSK-683', 'INT-TSK-684', 'INT-TSK-685', 'INT-TSK-686',
      'INT-TSK-687', 'INT-TSK-688', 'INT-TSK-689', 'INT-TSK-690', 'INT-TSK-691',
    ],
    byLabel: [],
  },
}
