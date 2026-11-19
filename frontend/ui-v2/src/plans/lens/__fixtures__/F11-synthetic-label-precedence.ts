import { task, type GoldenFixture } from './builders'

/**
 * F11, synthetic: label precedence over title. Derived from F6's shape with `wave` set so that labels and titles
 * disagree. Synthetic because no production record carried a `wave` on 2026-11-19 (DOC-F3E7C341EB27 section 2);
 * re-cut it against the first real plan that uses the field and retire this one.
 */
export const F11: GoldenFixture = {
  id: 'F11',
  plan_id: 'SYN-PLN-011',
  name: 'F11 synthetic: wave beats the title (step 1 over step 3)',
  shape: 'label',
  synthetic: true,
  objectives: ['ENC-TSK-S81', 'ENC-TSK-S82', 'ENC-TSK-S84', 'ENC-TSK-S88'],
  rows: [
    task('ENC-TSK-S81', 'W1 Component registry list', { wave: 'W1' }),
    // Titled W2-A but labelled W1: the label wins, so it lands in W1 against its title.
    task('ENC-TSK-S82', 'W2-A Approve flow', { wave: 'W1' }),
    // Titled W3 but labelled W2.
    task('ENC-TSK-S84', 'W3 Registry search', { wave: 'W2' }),
    // Names no wave, but a labelled objective is never Unassigned.
    task('ENC-TSK-S88', 'Fix cache invalidation on component approve', { wave: 'W2' }),
  ],
  expected: {
    // Labels are opaque: the resolver does not notice that "W1" looks numeric, so series and number stay null.
    waves: [
      { series: null, number: null, label: 'W1', parent_id: null, placement: 'label', members: ['ENC-TSK-S81', 'ENC-TSK-S82'] },
      { series: null, number: null, label: 'W2', parent_id: null, placement: 'label', members: ['ENC-TSK-S84', 'ENC-TSK-S88'] },
    ],
    chips: [],
    unassigned: [],
    byTitle: [],
    byLabel: ['ENC-TSK-S81', 'ENC-TSK-S82', 'ENC-TSK-S84', 'ENC-TSK-S88'],
  },
}
