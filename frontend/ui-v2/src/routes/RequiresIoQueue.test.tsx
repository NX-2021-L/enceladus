import { describe, expect, it, vi } from 'vitest'
import { ApprovalDecisionError } from '../approvals/types'

vi.mock('../auth/useCan', () => ({ useCanExecute: () => true }))
import { draftValid } from './RequiresIoQueue'
import { decideProposal, type ComponentProposal } from '../api/components'

const P: ComponentProposal = { component_id: 'cprop-0123456789', component_name: 'N', project_id: 'enceladus', category: 'lambda', version: 3 }

describe('draft validation', () => {
  it('approve needs a comp- ID', () => {
    expect(draftValid('approve', { id: 'comp-ok-1', floor: 'code', reason: '' })).toBe(true)
    expect(draftValid('approve', { id: 'Comp-x', floor: 'code', reason: '' })).toBe(false)
    expect(draftValid('approve', { id: 'cprop-0123456789', floor: 'code', reason: '' })).toBe(false)
  })
  it('reject needs 10+ chars', () => {
    expect(draftValid('reject', { id: '', floor: 'code', reason: 'too short' })).toBe(false)
    expect(draftValid('reject', { id: '', floor: 'code', reason: '  ten chars!  ' })).toBe(true)
  })
})

describe('decideProposal', () => {
  it('approve sends If-Match and the body', async () => {
    const f = vi.fn(async () => new Response(JSON.stringify({ approved_component_id: 'comp-new', proposal_status: 'approved' }), { status: 200 }))
    vi.stubGlobal('fetch', f)
    const out = await decideProposal(P, 'approve', { verdict: 'approve', component_id: 'comp-new', required_transition_type: 'code' })
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toMatch(/components\/cprop-0123456789\/approve$/)
    expect((init.headers as Record<string, string>)['If-Match']).toBe('3')
    expect(JSON.parse(init.body as string)).toEqual({ component_id: 'comp-new', required_transition_type: 'code' })
    expect(out.component_id).toBe('comp-new')
  })
  it('reject sends reason; 412 carries the refreshed proposal', async () => {
    const fresh = { ...P, version: 4 }
    const f = vi.fn(async () => new Response(JSON.stringify({ error: 'stale', proposal: fresh }), { status: 412 }))
    vi.stubGlobal('fetch', f)
    const err = await decideProposal(P, 'reject', { verdict: 'reject', rejection_reason: 'duplicate of x' }).catch((e) => e)
    expect(err).toBeInstanceOf(ApprovalDecisionError)
    expect(err.status).toBe(412)
    expect(err.refreshed.version).toBe(4)
    expect(JSON.parse((f.mock.calls[0] as unknown as [string, RequestInit])[1].body as string)).toEqual({ rejection_reason: 'duplicate of x' })
  })
  it('409 has no refreshed item', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'ID taken' }), { status: 409 })))
    const err = await decideProposal(P, 'approve', { verdict: 'approve', component_id: 'comp-a', required_transition_type: 'code' }).catch((e) => e)
    expect(err.status).toBe(409)
    expect(err.refreshed).toBeUndefined()
  })
})
