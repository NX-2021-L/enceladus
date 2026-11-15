import { describe, expect, it } from 'vitest'
import { previewFor } from '@io-kit/notify'
import { escalationCatalog } from './escalationCatalog'

describe('component proposal notification type', () => {
  it('is registered under the components group', () => {
    expect(escalationCatalog.types.component_proposal).toMatchObject({ label: 'Component proposal', group: 'components' })
    expect(escalationCatalog.groups.map((g) => g.id)).toContain('components')
  })
  it('previews generic and detailed text', () => {
    expect(previewFor(escalationCatalog, 'component_proposal', 0)?.title).toBe('Component proposal')
    expect(previewFor(escalationCatalog, 'component_proposal', 1)?.body).toBe('devops: Rotate signing key')
  })
})
