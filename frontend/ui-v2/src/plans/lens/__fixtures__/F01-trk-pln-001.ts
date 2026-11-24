import { kids, task, type GoldenFixture } from './builders'

/** F1, TRK-PLN-001: shape 1, hierarchical wave parents with word-form titles (`[Wave N] ...`). */
export const F1: GoldenFixture = {
  id: 'F1',
  plan_id: 'TRK-PLN-001',
  name: 'F1 TRK-PLN-001 hierarchical wave parents, word-form titles',
  shape: '1',
  synthetic: false,
  objectives: ['TRK-TSK-001', 'TRK-TSK-002', 'TRK-TSK-003', 'TRK-TSK-004', 'TRK-TSK-005', 'TRK-TSK-006', 'TRK-TSK-007'],
  rows: [
    task('TRK-TSK-001', '[Wave 1] Foundations'),
    ...kids('TRK-TSK-001', [
      ['TRK-TSK-001-0A', 'Schema and migrations'],
      ['TRK-TSK-001-0B', 'Seed data'],
    ]),
    task('TRK-TSK-002', '[Wave 2] Capture'),
    ...kids('TRK-TSK-002', [
      ['TRK-TSK-002-0A', 'Capture form'],
      ['TRK-TSK-002-0B', 'Capture validation'],
    ]),
    task('TRK-TSK-003', '[Wave 3] Review'),
    ...kids('TRK-TSK-003', [['TRK-TSK-003-0A', 'Review queue']]),
    task('TRK-TSK-004', '[Wave 4] Reporting'),
    // Three levels below the objective: child, grandchild, great-grandchild. All are members.
    ...kids('TRK-TSK-004', [['TRK-TSK-004-0A', 'Report builder']]),
    ...kids('TRK-TSK-004-0A', [['TRK-TSK-004-0A1', 'Report filters']]),
    ...kids('TRK-TSK-004-0A1', [['TRK-TSK-004-0A1a', 'Date range filter']]),
    ...kids('TRK-TSK-004', [['TRK-TSK-004-0B', 'Report export']]),
    task('TRK-TSK-005', '[Wave 5] Alerts'),
    ...kids('TRK-TSK-005', [['TRK-TSK-005-0A', 'Alert rules']]),
    task('TRK-TSK-006', '[Wave 6] Hardening'),
    ...kids('TRK-TSK-006', [
      ['TRK-TSK-006-0A', 'Load test'],
      ['TRK-TSK-006-0B', 'Backup drill'],
    ]),
    task('TRK-TSK-007', '[Wave 7] Launch'),
    ...kids('TRK-TSK-007', [['TRK-TSK-007-0A', 'Cutover']]),
  ],
  expected: {
    waves: [
      { series: 'W', number: 1, label: 'W1', parent_id: 'TRK-TSK-001', placement: 'parent', members: ['TRK-TSK-001-0A', 'TRK-TSK-001-0B'] },
      { series: 'W', number: 2, label: 'W2', parent_id: 'TRK-TSK-002', placement: 'parent', members: ['TRK-TSK-002-0A', 'TRK-TSK-002-0B'] },
      { series: 'W', number: 3, label: 'W3', parent_id: 'TRK-TSK-003', placement: 'parent', members: ['TRK-TSK-003-0A'] },
      {
        series: 'W',
        number: 4,
        label: 'W4',
        parent_id: 'TRK-TSK-004',
        placement: 'parent',
        members: ['TRK-TSK-004-0A', 'TRK-TSK-004-0A1', 'TRK-TSK-004-0A1a', 'TRK-TSK-004-0B'],
      },
      { series: 'W', number: 5, label: 'W5', parent_id: 'TRK-TSK-005', placement: 'parent', members: ['TRK-TSK-005-0A'] },
      { series: 'W', number: 6, label: 'W6', parent_id: 'TRK-TSK-006', placement: 'parent', members: ['TRK-TSK-006-0A', 'TRK-TSK-006-0B'] },
      { series: 'W', number: 7, label: 'W7', parent_id: 'TRK-TSK-007', placement: 'parent', members: ['TRK-TSK-007-0A'] },
    ],
    chips: [],
    unassigned: [],
    byTitle: [],
    byLabel: [],
  },
}
