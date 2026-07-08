import { describe, expect, it } from 'vitest'
import { openTasksSearchFor } from './HomeRoute'
import { parseFilterQuery } from '../search/feedSearchParams'

/**
 * ENC-TSK-M36 (feed data-truth, AC-3) -- the "Awaiting checkout" Home tile
 * counts a SINGLE project (api/homeQueue.ts::fetchAwaitingCheckoutCount), but
 * its destination Feed link used to carry no project_id token at all, so the
 * number shown on the tile and the number of rows Feed actually displayed
 * could disagree the moment another project also had awaiting-checkout
 * tasks. This locks in that the generated filter always scopes to the same
 * project the count was computed for.
 */
describe('openTasksSearchFor', () => {
  it('scopes the destination Feed filter to the given project', () => {
    const search = openTasksSearchFor('enceladus')
    const parsed = parseFilterQuery(search.f, search.op)
    const propertyKeys = parsed.tokens.map((t) => t.propertyKey)
    expect(propertyKeys).toContain('project_id')

    const projectToken = parsed.tokens.find((t) => t.propertyKey === 'project_id')
    expect(projectToken).toEqual({ propertyKey: 'project_id', operator: '=', value: 'enceladus' })
  })

  it('still carries the pre-existing status/record_type/checkout_state tokens', () => {
    const search = openTasksSearchFor('some-other-project')
    const parsed = parseFilterQuery(search.f, search.op)
    const byKey = Object.fromEntries(parsed.tokens.map((t) => [t.propertyKey, t]))
    expect(byKey.status).toEqual({ propertyKey: 'status', operator: '=', value: 'open' })
    expect(byKey.record_type).toEqual({ propertyKey: 'record_type', operator: '=', value: 'task' })
    expect(byKey.checkout_state).toEqual({
      propertyKey: 'checkout_state',
      operator: '!=',
      value: 'checked_out',
    })
  })

  it('changes with the project so two different projects never collide', () => {
    const a = openTasksSearchFor('enceladus')
    const b = openTasksSearchFor('harrisonfamily')
    expect(a.f).not.toBe(b.f)
  })
})
