import { describe, expect, it, vi } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { ExecuteMachine, createDegradedCounter, createExecuteClient, mintedFields } from '@io-kit/schema_form/execute'
import { resolveCall } from '@io-kit/schema_form/execute'
import { adaptResponse, buildEnvelope, createActionsTransport } from '../api/actions'
import { ACTION_COMMANDS, matchActionCommands } from './commands'
import { BESPOKE_ACTIONS, FLAGGED_ACTIONS, loadActionRegistry } from './registry'
import capsFull from './capsFull.json'

describe('generic coverage registry', () => {
  it('stays identical to the MCP server caps and flag list', () => {
    const upstream = resolve(__dirname, '../../../../tools/enceladus-mcp-server/parity/caps.json')
    if (existsSync(upstream)) expect(JSON.parse(readFileSync(upstream, 'utf8'))).toEqual(capsFull)
    const flagged = (capsFull.actions as Array<{ name: string; flag?: string }>).filter((a) => a.flag).map((a) => a.name)
    expect([...FLAGGED_ACTIONS].sort()).toEqual(flagged.sort())
  })

  it('covers all 82 flags-off actions; palette lists each without a bespoke route', async () => {
    const reg = await loadActionRegistry()
    expect(reg.contracts).toHaveLength(82)
    expect(reg.contracts.every((c) => c.inputSchema)).toBe(true)
    const names = new Set(ACTION_COMMANDS.map((c) => c.name))
    for (const c of reg.contracts) expect(names.has(c.action)).toBe(!BESPOKE_ACTIONS.has(c.action))
    expect(matchActionCommands('tracker.cre').length).toBeGreaterThan(0)
    expect(matchActionCommands('x')).toEqual([])
  })
})

describe('transport adapter', () => {
  const req = (phase: 'dry_run' | 'execute') => ({ phase, surface: 'enceladus', action: 'a.b', headers: {}, body: { arguments: { x: 1 }, schemaHash: 'h' } })
  it('builds an execute envelope and unwraps the per-step resolved_call', () => {
    expect(buildEnvelope(req('dry_run'), 'execute')).toMatchObject({ via: 'execute', dry_run: true, steps: [{ action: 'a.b', arguments: { x: 1 } }] })
    const rc = { v: 1 }
    expect(adaptResponse(req('dry_run'), 200, { step_results: [{ resolved_call: rc }] }).body).toBe(rc)
    expect(adaptResponse(req('dry_run'), 409, { title: 'p' })).toEqual({ status: 409, body: { title: 'p' } })
    expect(adaptResponse(req('execute'), 200, { step_results: [{ ok: true, minted: { '/id': 'DVP-TSK-1' } }] }).body).toMatchObject({ ok: true, minted: { '/id': 'DVP-TSK-1' } })
  })
})

// AC2: one read and one governed write, preview then execute with an Idempotency-Key; fake server only.
describe('dry-run preview then execute', () => {
  async function run(action: string, values: unknown) {
    const reg = await loadActionRegistry()
    const contract = reg.get(action)!
    const seen: Array<{ dry: boolean; key: string | null }> = []
    vi.stubGlobal('fetch', vi.fn(async (_u: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body))
      const key = new Headers(init.headers).get('Idempotency-Key')
      seen.push({ dry: body.dry_run, key })
      const step = body.steps[0]
      if (body.dry_run) {
        const rc = { ...resolveCall(contract, step.arguments), source: 'server-dry-run', schemaHash: body.schema_hash, idempotencyKey: key }
        return new Response(JSON.stringify({ step_results: [{ resolved_call: rc }] }), { status: 200 })
      }
      const minted: Record<string, string> = {}
      for (const f of mintedFields(contract.outputSchema)) minted[f.pointer] = 'DVP-TSK-900'
      return new Response(JSON.stringify({ step_results: [{ ok: true, structuredContent: { ok: true }, minted }] }), { status: 200 })
    }))
    const degraded = createDegradedCounter()
    const client = createExecuteClient({ transport: createActionsTransport(reg.via), onDegraded: degraded.record, liveSchemaHash: () => contract.schemaHash })
    const m = new ExecuteMachine(client, contract)
    await m.preview(values)
    expect(m.state.call?.source).toBe('server-dry-run')
    m.confirm(m.state.confirmLevel === 'typed' ? action : undefined)
    const receipt = await m.execute()
    vi.unstubAllGlobals()
    return { receipt, seen, degraded, contract }
  }

  it('read action (documents.check_policy): zero writes, no degraded run', async () => {
    const { receipt, seen, degraded } = await run('documents.check_policy', { title: 't', document_subtype: 'note' })
    expect(receipt?.ok).toBe(true)
    expect(receipt?.call.sideEffects.writeCount).toBe(0)
    expect(seen[0].dry).toBe(true)
    expect(seen[1].key).toBe(seen[0].key)
    expect(degraded.count('enceladus', 'documents.check_policy')).toBe(0)
  })

  it('governed write action: Idempotency-Key sent, minted ids come only from the server', async () => {
    const reg = await loadActionRegistry()
    const write = reg.contracts.find((c) => c.dryRun && !c.annotations.readOnlyHint && mintedFields(c.outputSchema).length > 0)
    expect(write).toBeDefined()
    const { receipt, seen } = await run(write!.action, {})
    expect(seen.every((s) => !!s.key)).toBe(true)
    expect(receipt?.unfilled).toEqual([])
    expect(receipt?.filled.length).toBeGreaterThan(0)
  })
})
