import { afterEach, describe, expect, it, vi } from 'vitest'
import { createDocument, DocumentWriteError, patchDocument } from './documentWrites'
import { extractGovernanceHash } from './actions'

const HASH = 'f3e5dfb91f8adf649814d1c72d853ca2ba6a36bcd519e327b6eac3ff7b9da55a'

/** MCP tools/call reply: the search tool text is the server's wrapped {success, result:{governance_hash}} envelope. */
const mcpReply = (payload: unknown, status = 200) =>
  new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: JSON.stringify(payload) }] } }), { status })

const wrapped = { success: true, action: 'governance.hash', result: { success: true, governance_hash: HASH } }

function routeFetch(mcp: () => Response, write: () => Response) {
  const calls: { url: string; init: RequestInit }[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init })
      return String(url).includes('/coordination/mcp') ? mcp() : write()
    }),
  )
  return calls
}

afterEach(() => vi.unstubAllGlobals())

describe('extractGovernanceHash', () => {
  it('reads the wrapped result envelope and the flat shapes', () => {
    expect(extractGovernanceHash(wrapped)).toBe(HASH)
    expect(extractGovernanceHash({ governance_hash: HASH })).toBe(HASH)
    expect(extractGovernanceHash({ hash: HASH })).toBe(HASH)
    expect(extractGovernanceHash({ success: true })).toBe('')
    expect(extractGovernanceHash('nope')).toBe('')
  })
})

describe('document writes send the governance hash (ENC-TSK-R93)', () => {
  it('createDocument PUT carries the hash read from the wrapped governance.hash reply', async () => {
    const calls = routeFetch(() => mcpReply(wrapped), () => new Response(JSON.stringify({ document_id: 'DOC-NEW000000001' }), { status: 201 }))
    const id = await createDocument({ project_id: 'enceladus', title: 'T', content: 'body', document_subtype: 'doc' })
    expect(id).toBe('DOC-NEW000000001')
    const put = calls.find((c) => c.init.method === 'PUT')!
    expect(put.url).toMatch(/\/documents$/)
    expect(JSON.parse(String(put.init.body))).toMatchObject({ governance_hash: HASH, title: 'T', content: 'body' })
  })

  it('patchDocument PATCH carries the hash and the if_match precondition', async () => {
    const calls = routeFetch(() => mcpReply(wrapped), () => new Response('{}', { status: 200 }))
    await patchDocument('DOC-ABC123456789', { content: 'x', if_match: 'h'.repeat(64) })
    const patch = calls.find((c) => c.init.method === 'PATCH')!
    expect(JSON.parse(String(patch.init.body))).toMatchObject({ governance_hash: HASH, if_match: 'h'.repeat(64) })
  })

  it('a missing hash surfaces the real cause and sends no write', async () => {
    const calls = routeFetch(() => mcpReply({ success: true, result: {} }), () => new Response('{}', { status: 200 }))
    const err = await createDocument({ project_id: 'p', title: 'T', content: '', document_subtype: 'doc' }).catch((e) => e)
    expect(err).toBeInstanceOf(DocumentWriteError)
    expect(err.code).toBe('GOVERNANCE_HASH_UNAVAILABLE')
    expect(err.message).toMatch(/governance hash unavailable: .*no hash/)
    expect(calls.some((c) => c.init.method === 'PUT')).toBe(false)
  })

  it('an MCP failure reports HTTP status and message; a write failure reports status and message', async () => {
    routeFetch(() => mcpReply({ title: 'Forbidden by policy', status: 403 }, 403), () => new Response('{}'))
    const e1 = await createDocument({ project_id: 'p', title: 'T', content: '', document_subtype: 'doc' }).catch((e) => e)
    expect(e1.message).toMatch(/HTTP 403.*Forbidden by policy/)

    routeFetch(() => mcpReply(wrapped), () => new Response(JSON.stringify({ error_envelope: { code: 'INVALID_INPUT', message: 'bad subtype' } }), { status: 400 }))
    const e2 = await createDocument({ project_id: 'p', title: 'T', content: '', document_subtype: 'x' }).catch((e) => e)
    expect(e2.message).toBe('bad subtype (HTTP 400)')
    expect(e2.status).toBe(400)
  })
})
