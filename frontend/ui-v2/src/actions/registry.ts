/**
 * DVP-TSK-895: the generic-coverage registry. Built from the Enceladus caps
 * (1.1.0, committed copy of tools/enceladus-mcp-server/parity/caps.json, kept
 * identical by registry.test.ts) through the kit's ActionRegistry. Flags-off
 * basis: an action with a `flag` appears when the flag turns on (a caps
 * regeneration), never before. Loaded lazily so the 150KB schema payload stays
 * out of the initial bundle.
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
export const FLAGGED_ACTIONS: ReadonlySet<string> = new Set(["component.add_edge", "component.advance", "component.deprecate", "component.propose", "component.remove_edge", "component.restore", "component.revert", "document.append_handoff_reply", "document.append_wave_entry", "document.claim_handoff", "document.complete_handoff", "document.create_coe", "document.create_handoff", "document.create_wave", "escalation.get", "escalation.list", "escalation.request", "escalation.watch", "tracker.archive_relationship", "tracker.create_lesson", "tracker.create_relationship", "tracker.extend_lesson", "tracker.list_lessons", "tracker.list_relationships"])

export interface FlaggedAction { name: string; flag?: string }

/** flags-off = no `flag` on the caps action. */
export function flagsOff<T extends FlaggedAction>(actions: readonly T[]): T[] {
  return actions.filter((a) => !a.flag)
}

let cached: Promise<{ contracts: ActionContract[]; get: (a: string) => ActionContract | undefined; via: (a: string) => string | undefined }> | undefined

export function loadActionRegistry() {
  cached ??= (async () => {
    const [{ ActionRegistry }, caps] = await Promise.all([import('@io-kit/schema_form'), import('./capsFull.json')])
    const file = (caps as { default: unknown }).default as { actions: Array<FlaggedAction & { via: string }> }
    const off = new Set(flagsOff(file.actions).map((a) => a.name))
    const viaMap = new Map(file.actions.map((a) => [a.name, a.via]))
    const registry = ActionRegistry.load([file])
    const contracts = registry.list().filter((c) => off.has(c.action))
    const byName = new Map(contracts.map((c) => [c.action, c]))
    return { contracts, get: (a: string) => byName.get(a), via: (a: string) => viaMap.get(a) }
  })()
  return cached
}
