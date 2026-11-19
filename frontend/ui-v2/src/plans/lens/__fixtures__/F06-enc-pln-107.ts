import { task, type GoldenFixture } from './builders'

/**
 * F6, ENC-PLN-107: shape 3, flat childless objectives in out-of-order objectives_set order, with one that names no wave.
 * Ordering is by number (W4 draws before W5 although S87 precedes S85), S83 joins the wave S82 founded instead of
 * founding a second wave 2, and S88 is never attached to its neighbour S85.
 */
export const F6: GoldenFixture = {
  id: 'F6',
  plan_id: 'ENC-PLN-107',
  name: 'F6 ENC-PLN-107 flat objectives, out of order, one Unassigned',
  shape: '3',
  synthetic: false,
  objectives: ['ENC-TSK-S81', 'ENC-TSK-S82', 'ENC-TSK-S83', 'ENC-TSK-S84', 'ENC-TSK-S87', 'ENC-TSK-S85', 'ENC-TSK-S88', 'ENC-TSK-S89'],
  rows: [
    task('ENC-TSK-S81', 'W1 Component registry list'),
    task('ENC-TSK-S82', 'W2-A Approve flow'),
    task('ENC-TSK-S83', 'W2-B Reject flow'),
    task('ENC-TSK-S84', 'W3 Registry search'),
    task('ENC-TSK-S87', 'W5-B Audit trail'),
    task('ENC-TSK-S85', 'W4 Strictness gate'),
    task('ENC-TSK-S88', 'Fix cache invalidation on component approve'),
    task('ENC-TSK-S89', 'W5-C Close out'),
  ],
  expected: {
    waves: [
      { series: 'W', number: 1, label: 'W1', parent_id: null, placement: 'title', members: ['ENC-TSK-S81'] },
      { series: 'W', number: 2, label: 'W2', parent_id: null, placement: 'title', members: ['ENC-TSK-S82', 'ENC-TSK-S83'] },
      { series: 'W', number: 3, label: 'W3', parent_id: null, placement: 'title', members: ['ENC-TSK-S84'] },
      { series: 'W', number: 4, label: 'W4', parent_id: null, placement: 'title', members: ['ENC-TSK-S85'] },
      { series: 'W', number: 5, label: 'W5', parent_id: null, placement: 'title', members: ['ENC-TSK-S87', 'ENC-TSK-S89'] },
    ],
    chips: [],
    unassigned: ['ENC-TSK-S88'],
    byTitle: ['ENC-TSK-S81', 'ENC-TSK-S82', 'ENC-TSK-S83', 'ENC-TSK-S84', 'ENC-TSK-S87', 'ENC-TSK-S85', 'ENC-TSK-S89'],
    byLabel: [],
  },
}
