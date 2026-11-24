import { kids, task, type GoldenFixture } from './builders'

/**
 * F2, HFY-PLN-004: shape 1, the wave token is not at the start of the title, and descendants carry `V1:`/`V2:`/`V3:`
 * deliverable variants in exactly the shape of a form-A token (spec section 3.4). They must not become phantom waves.
 */
export const F2: GoldenFixture = {
  id: 'F2',
  plan_id: 'HFY-PLN-004',
  name: 'F2 HFY-PLN-004 token not at start, descendant V1/V2/V3 near-miss',
  shape: '1',
  synthetic: false,
  objectives: ['HFY-TSK-386', 'HFY-TSK-387', 'HFY-TSK-388', 'HFY-TSK-389', 'HFY-TSK-390', 'HFY-TSK-391'],
  rows: [
    task('HFY-TSK-386', 'P-HFY-MEDIA W1 [wave-1] Ground truth'),
    ...kids('HFY-TSK-386', [
      ['HFY-TSK-392', 'V1: All media page and media detail page'],
      ['HFY-TSK-393', 'V2: comments on media detail pages'],
    ]),
    task('HFY-TSK-387', 'P-HFY-MEDIA W2 [wave-2] Upload path'),
    ...kids('HFY-TSK-387', [['HFY-TSK-394', 'V3: posts-page media carousel']]),
    task('HFY-TSK-388', 'P-HFY-MEDIA W3 [wave-3] Thumbnails'),
    ...kids('HFY-TSK-388', [['HFY-TSK-395', 'Thumbnail worker']]),
    task('HFY-TSK-389', 'P-HFY-MEDIA W4 [wave-4] Moderation'),
    ...kids('HFY-TSK-389', [['HFY-TSK-396', 'Moderation queue']]),
    task('HFY-TSK-390', 'P-HFY-MEDIA W5 [wave-5] Accessibility'),
    ...kids('HFY-TSK-390', [['HFY-TSK-397', 'Alt text prompts']]),
    task('HFY-TSK-391', 'P-HFY-MEDIA W6 [wave-6] Launch'),
    ...kids('HFY-TSK-391', [['HFY-TSK-398', 'Rollout checklist']]),
  ],
  expected: {
    waves: [
      { series: 'W', number: 1, label: 'W1', parent_id: 'HFY-TSK-386', placement: 'parent', members: ['HFY-TSK-392', 'HFY-TSK-393'] },
      { series: 'W', number: 2, label: 'W2', parent_id: 'HFY-TSK-387', placement: 'parent', members: ['HFY-TSK-394'] },
      { series: 'W', number: 3, label: 'W3', parent_id: 'HFY-TSK-388', placement: 'parent', members: ['HFY-TSK-395'] },
      { series: 'W', number: 4, label: 'W4', parent_id: 'HFY-TSK-389', placement: 'parent', members: ['HFY-TSK-396'] },
      { series: 'W', number: 5, label: 'W5', parent_id: 'HFY-TSK-390', placement: 'parent', members: ['HFY-TSK-397'] },
      { series: 'W', number: 6, label: 'W6', parent_id: 'HFY-TSK-391', placement: 'parent', members: ['HFY-TSK-398'] },
    ],
    chips: [],
    unassigned: [],
    byTitle: [],
    byLabel: [],
  },
}
