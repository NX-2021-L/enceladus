import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from '@tanstack/react-router'
import { SchemaForm } from '@io-kit/schema_form'
import type { ActionContract } from '@io-kit/schema_form'
import { ExecuteMachine, createDegradedCounter, createExecuteClient, renderPreview } from '@io-kit/schema_form/execute'
import type { MachineState } from '@io-kit/schema_form/execute'
import { createActionsTransport } from '../api/actions'
import { ACTION_COMMANDS } from './commands'
import { SURFACE, loadActionRegistry } from './registry'
import './actions.css'

export const EXECUTE_REQUIRES = 'io-dev-admin'
const degraded = createDegradedCounter()

/** /actions: index of every generically covered action. */
export function ActionsIndexRoute() {
  const [q, setQ] = useState('')
  const rows = ACTION_COMMANDS.filter((c) => (c.name + ' ' + c.title).toLowerCase().includes(q.toLowerCase()))
  return (
    <section className="actions-page" aria-label="Actions">
      <h1>Actions</h1>
      <p className="actions-note">Generated from the action registry. Execute requires {EXECUTE_REQUIRES}; bespoke screens keep precedence.</p>
      <input aria-label="Filter actions" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter actions" />
      <ul>
        {rows.map((c) => (
          <li key={c.name}>
            <Link to="/actions/$action" params={{ action: c.name }}>{c.name}</Link> <span>{c.title}</span>
            {c.readOnly ? <em> read</em> : <em> write</em>}
          </li>
        ))}
      </ul>
    </section>
  )
}

/** /actions/$action: generated form -> server dry-run ResolvedCall v1 preview -> execute -> receipt. */
export function ActionFormRoute() {
  const { action } = useParams({ strict: false }) as { action: string }
  const [contract, setContract] = useState<ActionContract | null | undefined>(undefined)
  const [via, setVia] = useState<(a: string) => string | undefined>(() => () => undefined)
  useEffect(() => {
    let live = true
    void loadActionRegistry().then((r) => {
      if (!live) return
      setContract(r.get(action) ?? null)
      setVia(() => r.via)
    })
    return () => {
      live = false
    }
  }, [action])
  if (contract === undefined) return <p className="actions-note">Loading action registry…</p>
  if (contract === null) return <p role="alert">Unknown action {action}</p>
  return <ActionForm key={contract.action} contract={contract} via={via} />
}

function ActionForm({ contract, via }: { contract: ActionContract; via: (a: string) => string | undefined }) {
  const machine = useMemo(() => {
    const client = createExecuteClient({
      transport: createActionsTransport(via),
      onDegraded: degraded.record,
      liveSchemaHash: (_s, a) => (a === contract.action ? contract.schemaHash : undefined),
    })
    return new ExecuteMachine(client, contract)
  }, [contract, via])
  const [state, setState] = useState<MachineState>(machine.state)
  const [typed, setTyped] = useState('')
  useEffect(() => machine.subscribe(setState), [machine])
  const preview = state.call ? renderPreview(state.call) : undefined
  const receipt = state.receipt
  return (
    <section className="actions-page" aria-label={contract.title}>
      <h1>{contract.title}</h1>
      <p className="actions-note">
        {contract.action} · confirm: {state.confirmLevel} · server dry-run: {contract.dryRun ? 'yes' : 'no (client preview, typed confirmation)'} · degraded runs: {degraded.count(SURFACE, contract.action)}
      </p>
      <SchemaForm
        contract={contract}
        submitLabel="Dry run"
        onValueChange={(v) => machine.edit(v)}
        onSubmit={(args) => void machine.preview(args)}
        serverProblem={receipt?.problem ? { ...receipt.problem, errors: receipt.problem.errors ?? [] } : null}
      />
      {state.status === 'previewing' ? <p role="status">Resolving call on the server…</p> : null}
      {state.error ? <p role="alert">{state.error}</p> : null}
      {preview ? (
        <div className="actions-preview" aria-label="Resolved call preview">
          <h2>Preview ({preview.verification})</h2>
          {preview.banner ? <p role="alert">{preview.banner}</p> : null}
          {preview.externalEffectBanner ? <p role="alert">{preview.externalEffectBanner}</p> : null}
          <p>{preview.sentence}</p>
          <p>{preview.sideEffects}</p>
          {preview.placeholders.length ? <p>Minted by the server: {preview.placeholders.join(', ')}</p> : null}
          <pre>{preview.json}</pre>
          {state.confirmLevel === 'typed' ? (
            <label>
              Type {contract.action} to confirm
              <input value={typed} onChange={(e) => setTyped(e.target.value)} />
            </label>
          ) : null}
          <button
            type="button"
            disabled={!state.call || state.status === 'executing' || state.status === 'previewing' || state.status === 'done'}
            onClick={() => {
              if (machine.confirm(state.confirmLevel === 'typed' ? typed : undefined)) void machine.execute()
            }}
          >
            Execute
          </button>
        </div>
      ) : null}
      {receipt ? (
        <div className="actions-receipt" aria-label="Receipt">
          <h2>{receipt.ok ? 'Receipt' : 'Failed'}{receipt.stale ? ' (registry changed, preview again)' : ''}</h2>
          {receipt.filled.map((f) => (
            <p key={f.pointer}>{f.label}: <code>{f.id}</code></p>
          ))}
          {receipt.unfilled.map((u) => (
            <p key={u.pointer}>{u.label}: not returned by the server</p>
          ))}
          <p>Idempotency-Key {receipt.idempotencyKey}</p>
          <pre>{JSON.stringify(receipt.structuredContent ?? receipt.problem ?? null, null, 2)}</pre>
        </div>
      ) : null}
    </section>
  )
}
