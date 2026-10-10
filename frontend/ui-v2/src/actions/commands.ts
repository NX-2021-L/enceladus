/** DVP-TSK-895: palette commands, one per flags-off action without a bespoke route. Light index (no schemas). */
import capsSnapshot from '../shell/capsSnapshot.json'
import { BESPOKE_ACTIONS, FLAGGED_ACTIONS } from './registry'

export interface ActionCommand { name: string; title: string; readOnly: boolean }

type SnapAction = { name: string; title: string; flag?: string; annotations?: { readOnlyHint?: boolean } }

export const ACTION_COMMANDS: ActionCommand[] = (capsSnapshot.actions as SnapAction[])
  .filter((a) => !FLAGGED_ACTIONS.has(a.name) && !BESPOKE_ACTIONS.has(a.name))
  .map((a) => ({ name: a.name, title: a.title, readOnly: a.annotations?.readOnlyHint === true }))
  .sort((a, b) => a.name.localeCompare(b.name))

export function matchActionCommands(query: string, limit = 6): ActionCommand[] {
  const q = query.trim().toLowerCase()
  if (q.length < 2) return []
  return ACTION_COMMANDS.filter((c) => c.name.toLowerCase().includes(q) || c.title.toLowerCase().includes(q)).slice(0, limit)
}
