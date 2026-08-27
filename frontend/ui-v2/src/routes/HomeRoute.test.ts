import { describe, expect, it } from 'vitest'
import { OPEN_TASKS_SEARCH } from './HomeRoute'
import { parseFilterQuery } from '../search/feedSearchParams'

/**
 * ENC-TSK-P59 (ENC-ISS-725, supersedes the ENC-TSK-M36 single-project
 * scoping) -- the "Awaiting checkout" Home tile now counts EVERY project
 * (api/homeQueue.ts::fetchAwaitingCheckoutCountAll sums the per-project
 * tracker counts), so its destination Feed filter must carry the
 * status/record_type/checkout_state pills ONLY. A project_id token here
 * would reintroduce the UAT H3 defect: a global-looking number whose link
 * opens a single arbitrary project's rows (0 hits). Both sides measuring
 * all projects is what keeps the tile number and the Feed rows in
 * agreement -- the M36 data-truth invariant, preserved under the new scope.
 */
describe('OPEN_TASKS_SEARCH (awaiting-checkout tile destination)', () => {
  it('carries the status/record_type/checkout_state tokens', () => {
    const parsed = parseFilterQuery(OPEN_TASKS_SEARCH.f, OPEN_TASKS_SEARCH.op)
    const byKey = Object.fromEntries(parsed.tokens.map((t) => [t.propertyKey, t]))
    expect(byKey.status).toEqual({ propertyKey: 'status', operator: '=', value: 'open' })
    expect(byKey.record_type).toEqual({ propertyKey: 'record_type', operator: '=', value: 'task' })
    expect(byKey.checkout_state).toEqual({
      propertyKey: 'checkout_state',
      operator: '!=',
      value: 'checked_out',
    })
  })

  it('is NOT scoped to any single project (the count is cross-project)', () => {
    const parsed = parseFilterQuery(OPEN_TASKS_SEARCH.f, OPEN_TASKS_SEARCH.op)
    const propertyKeys = parsed.tokens.map((t) => t.propertyKey)
    expect(propertyKeys).not.toContain('project_id')
    expect(parsed.tokens).toHaveLength(3)
  })
})
