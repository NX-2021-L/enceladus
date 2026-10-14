/**
 * DVP-TSK-895: the generic-coverage registry. Built from the Enceladus caps
 * (1.1.0, committed copy of tools/enceladus-mcp-server/parity/caps.json, kept
 * identical by registry.test.ts) through the kit's ActionRegistry. Flags-off
 * basis plus DEFAULT_ON_FLAGS: an action with a `flag` appears when the flag turns
 * on (a caps regeneration), never before, except the flags that are already ON in
 * prod. Loaded lazily so the 150KB schema payload stays out of the initial bundle.
 */
import type { ActionContract } from '@io-kit/schema_form'

export const SURFACE = 'enceladus'

/** Actions served by a bespoke screen; the generic form still exists but the bespoke route keeps precedence. */
export const BESPOKE_ACTIONS: ReadonlySet<string> = new Set([
  'projects.list', 'tracker.get', 'documents.search', 'documents.get', 'documents.list',
  'documents.manifest', 'documents.history', 'documents.diff', 'changelog.history',
  'tracker.graphsearch', 'escalation.list', 'agent.list', 'agent.type.list', 'checkout.task',
])

/** Flag-gated actions (kept equal to capsFull.json by registry.test.ts; they appear when a caps regeneration drops the flag). */
export const FLAGGED_ACTIONS: ReadonlySet<string> = new Set(["component.add_edge", "component.advance", "component.deprecate", "component.propose", "component.remove_edge", "component.restore", "component.revert", "document.append_handoff_reply", "document.append_wave_entry", "document.claim_handoff", "document.complete_handoff", "document.create_coe", "document.create_handoff", "document.create_wave", "escalation.get", "escalation.list", "escalation.request", "escalation.watch", "recipe.create", "recipe.deprecate", "recipe.get", "recipe.list", "recipe.publish_request", "recipe.validate", "recipe_run.cancel", "recipe_run.get", "recipe_run.list", "recipe_run.resume", "recipe_run.start", "tracker.archive_relationship", "tracker.create_lesson", "tracker.create_relationship", "tracker.extend_lesson", "tracker.list_lessons", "tracker.list_relationships"])

/**
 * DVP-TSK-B35: flags that are ON by default in prod (server.py ENABLE_ESCALATION_PRIMITIVE default=True, and
 * ActionFeatureFlags.enable_escalation_primitive). Their actions are live, so the UI serves them (bespoke
 * /escalations for escalation.list, the generated form for the rest) and the parity ratchet counts them: keep
 * this equal to PARITY_FLAGS in .github/workflows/parity-report.yml.
 */
export const DEFAULT_ON_FLAGS: ReadonlySet<string> = new Set(['enable_escalation_primitive'])

/** The flagged actions whose flag is in DEFAULT_ON_FLAGS (kept equal to capsFull.json by registry.test.ts). */
export const DEFAULT_ON_ACTIONS: ReadonlySet<string> = new Set(['escalation.get', 'escalation.list', 'escalation.request', 'escalation.watch'])

export interface FlaggedAction { name: string; flag?: string }

/** live = no `flag` on the caps action, or a flag that is on by default in prod. */
export function liveActions<T extends FlaggedAction>(actions: readonly T[]): T[] {
  return actions.filter((a) => !a.flag || DEFAULT_ON_FLAGS.has(a.flag))
}

let cached: Promise<{ contracts: ActionContract[]; get: (a: string) => ActionContract | undefined; via: (a: string) => string | undefined }> | undefined

export function loadActionRegistry() {
  cached ??= (async () => {
    const [{ ActionRegistry }, caps] = await Promise.all([import('@io-kit/schema_form'), import('./capsFull.json')])
    const file = (caps as { default: unknown }).default as { actions: Array<FlaggedAction & { via: string }> }
    const off = new Set(liveActions(file.actions).map((a) => a.name))
    const viaMap = new Map(file.actions.map((a) => [a.name, a.via]))
    const registry = ActionRegistry.load([file])
    const contracts = registry.list().filter((c) => off.has(c.action))
    const byName = new Map(contracts.map((c) => [c.action, c]))
    return { contracts, get: (a: string) => byName.get(a), via: (a: string) => viaMap.get(a) }
  })()
  return cached
}
