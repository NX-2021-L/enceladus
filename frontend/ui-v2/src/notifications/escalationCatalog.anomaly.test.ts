/** ENC-TSK-R80-0G (ENC-FTR-150 AC-7): the anomaly row is in the Settings catalog; generic mode carries issue_id only. */
import { describe, expect, it } from 'vitest'
import { anomalyPushFields, previewFor } from '@io-kit/notify'
import { escalationCatalog } from './escalationCatalog'

describe('anomaly notification type', () => {
  it('is registered in the catalog with no minimum-risk select', () => {
    expect(escalationCatalog.types.anomaly).toMatchObject({ label: 'Anomaly', group: 'anomalies', risk: false })
    expect(escalationCatalog.groups.map((g) => g.id)).toContain('anomalies')
  })
  it('previews generic and detailed text', () => {
    expect(previewFor(escalationCatalog, 'anomaly', 0)?.body).toBe('An anomaly was filed in Enceladus')
    expect(previewFor(escalationCatalog, 'anomaly', 1)?.body).toBe('AWS Lambda · $41.20')
  })
  it('generic push fields are issue_id only', () => {
    expect(anomalyPushFields(0, { issue_id: 'ENC-ISS-1', service: 'Lambda', impact: '$9' })).toEqual({ issue_id: 'ENC-ISS-1' })
  })
})
