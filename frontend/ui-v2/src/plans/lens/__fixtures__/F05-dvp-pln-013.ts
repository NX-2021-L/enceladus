import { kids, task, type GoldenFixture } from './builders'

/**
 * F5, DVP-PLN-013: shape 2, children linked only by `parent`, and the production disagreement. DVP-TSK-974 is titled
 * `E4-W3.1` and DVP-TSK-962 (W3) lists it in `subtask_ids`, yet its `parent` is DVP-TSK-961, which is W2. Parent
 * pointers decide, so it is a member of W2. The row for 962 carries that `subtask_ids` entry on purpose: the resolver
 * must ignore it.
 */
export const F5: GoldenFixture = {
  id: 'F5',
  plan_id: 'DVP-PLN-013',
  name: 'F5 DVP-PLN-013 children by parent only; DVP-TSK-974 parent, subtask_ids and title disagree',
  shape: '2',
  synthetic: false,
  objectives: ['DVP-TSK-959', 'DVP-TSK-960', 'DVP-TSK-961', 'DVP-TSK-962', 'DVP-TSK-963', 'DVP-TSK-988'],
  rows: [
    task('DVP-TSK-959', 'E4-W0 io decisions'),
    task('DVP-TSK-960', 'E4-W1 Contract'),
    task('DVP-TSK-961', 'E4-W2 Build'),
    task('DVP-TSK-962', 'E4-W3 Verify', { subtask_ids: ['DVP-TSK-969', 'DVP-TSK-974'] }),
    task('DVP-TSK-963', 'E4-W4 Deploy'),
    task('DVP-TSK-988', 'E4-W5 Exit'),
    // The children carry unrelated id series and are linked only by `parent`.
    ...kids('DVP-TSK-959', [['DVP-TSK-964', 'Record the rulings'], ['DVP-TSK-965', 'Freeze the contract']]),
    ...kids('DVP-TSK-960', [['DVP-TSK-966', 'Wire format'], ['DVP-TSK-967', 'Dictionary entry']]),
    ...kids('DVP-TSK-961', [['DVP-TSK-968', 'Handler']]),
    task('DVP-TSK-974', 'E4-W3.1 Telemetry probe', { parent: 'DVP-TSK-961' }),
    ...kids('DVP-TSK-962', [['DVP-TSK-969', 'Gamma proof'], ['DVP-TSK-970', 'Regression sweep']]),
    ...kids('DVP-TSK-963', [['DVP-TSK-971', 'Prod promote']]),
    ...kids('DVP-TSK-988', [['DVP-TSK-987', 'Exit report']]),
  ],
  expected: {
    waves: [
      { series: 'W', number: 0, label: 'W0', parent_id: 'DVP-TSK-959', placement: 'parent', members: ['DVP-TSK-964', 'DVP-TSK-965'] },
      { series: 'W', number: 1, label: 'W1', parent_id: 'DVP-TSK-960', placement: 'parent', members: ['DVP-TSK-966', 'DVP-TSK-967'] },
      { series: 'W', number: 2, label: 'W2', parent_id: 'DVP-TSK-961', placement: 'parent', members: ['DVP-TSK-968', 'DVP-TSK-974'] },
      { series: 'W', number: 3, label: 'W3', parent_id: 'DVP-TSK-962', placement: 'parent', members: ['DVP-TSK-969', 'DVP-TSK-970'] },
      { series: 'W', number: 4, label: 'W4', parent_id: 'DVP-TSK-963', placement: 'parent', members: ['DVP-TSK-971'] },
      { series: 'W', number: 5, label: 'W5', parent_id: 'DVP-TSK-988', placement: 'parent', members: ['DVP-TSK-987'] },
    ],
    chips: [],
    unassigned: [],
    byTitle: [],
    byLabel: [],
  },
}
