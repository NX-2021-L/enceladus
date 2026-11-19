import { kids, task, type GoldenFixture } from './builders'

/**
 * F3, ENC-PLN-102: shapes 1 and 6. The leading `4.1` is a version number, not a wave. Seven childless objectives name
 * their wave in the title and join the nearest preceding wave of that number (step 3); three of them are DVP-* ids
 * inside an ENC plan. The W1 parent's title narrates its dependency on W0, so only the FIRST token may count.
 */
export const F3: GoldenFixture = {
  id: 'F3',
  plan_id: 'ENC-PLN-102',
  name: 'F3 ENC-PLN-102 version-number trap, cross-project objectives, step 3 joins',
  shape: '1, 6',
  synthetic: false,
  objectives: [
    'ENC-TSK-R80',
    'DVP-TSK-B87',
    'DVP-TSK-B88',
    'DVP-TSK-B89',
    'ENC-TSK-R81',
    'ENC-TSK-R93',
    'ENC-TSK-R82',
    'ENC-TSK-R90',
    'ENC-TSK-R92',
    'ENC-TSK-R83',
    'ENC-TSK-R91',
    'ENC-TSK-R84',
  ],
  rows: [
    task('ENC-TSK-R80', '4.1 W0 -- Truth and foundations'),
    ...kids('ENC-TSK-R80', [
      ['ENC-TSK-R80-0A', 'Freeze the row contract'],
      ['ENC-TSK-R80-0B', 'Baseline measurements'],
    ]),
    task('DVP-TSK-B87', '4.1 W0.12 Seed fixtures for the cockpit'),
    task('DVP-TSK-B88', '4.1 W0.13 Seed fixtures for retrieval'),
    task('DVP-TSK-B89', '4.1 W0.14 Seed fixtures for identity'),
    task(
      'ENC-TSK-R81',
      '4.1 W1 -- Signals, identity, cockpit and retrieval first layer (wave parent; children parallel, depend on W0 only)',
    ),
    ...kids('ENC-TSK-R81', [
      ['ENC-TSK-R81-0A', 'Signal ingestion'],
      ['ENC-TSK-R81-0B', 'Identity map'],
      ['ENC-TSK-R81-0C', 'Cockpit shell'],
    ]),
    task('ENC-TSK-R93', '4.1 W1.7b Retrieval smoke test'),
    task('ENC-TSK-R82', '4.1 W2 -- Graph layer'),
    ...kids('ENC-TSK-R82', [['ENC-TSK-R82-0A', 'Edge projection']]),
    task('ENC-TSK-R90', '4.1 W2.1b Edge weights'),
    task('ENC-TSK-R92', '4.1 W2.6b Edge decay'),
    task('ENC-TSK-R83', '4.1 W3 -- Ranking'),
    ...kids('ENC-TSK-R83', [
      ['ENC-TSK-R83-0A', 'Ranker'],
      ['ENC-TSK-R83-0B', 'Ranker evaluation'],
    ]),
    task('ENC-TSK-R91', '4.1 W3.4b Ranker rollback'),
    task('ENC-TSK-R84', '4.1 W4 -- Exit'),
    ...kids('ENC-TSK-R84', [['ENC-TSK-R84-0A', 'Exit report']]),
  ],
  expected: {
    waves: [
      {
        series: 'W',
        number: 0,
        label: 'W0',
        parent_id: 'ENC-TSK-R80',
        placement: 'parent',
        members: ['ENC-TSK-R80-0A', 'ENC-TSK-R80-0B', 'DVP-TSK-B87', 'DVP-TSK-B88', 'DVP-TSK-B89'],
      },
      {
        series: 'W',
        number: 1,
        label: 'W1',
        parent_id: 'ENC-TSK-R81',
        placement: 'parent',
        members: ['ENC-TSK-R81-0A', 'ENC-TSK-R81-0B', 'ENC-TSK-R81-0C', 'ENC-TSK-R93'],
      },
      { series: 'W', number: 2, label: 'W2', parent_id: 'ENC-TSK-R82', placement: 'parent', members: ['ENC-TSK-R82-0A', 'ENC-TSK-R90', 'ENC-TSK-R92'] },
      { series: 'W', number: 3, label: 'W3', parent_id: 'ENC-TSK-R83', placement: 'parent', members: ['ENC-TSK-R83-0A', 'ENC-TSK-R83-0B', 'ENC-TSK-R91'] },
      { series: 'W', number: 4, label: 'W4', parent_id: 'ENC-TSK-R84', placement: 'parent', members: ['ENC-TSK-R84-0A'] },
    ],
    chips: [],
    unassigned: [],
    byTitle: ['DVP-TSK-B87', 'DVP-TSK-B88', 'DVP-TSK-B89', 'ENC-TSK-R93', 'ENC-TSK-R90', 'ENC-TSK-R92', 'ENC-TSK-R91'],
    byLabel: [],
  },
}
