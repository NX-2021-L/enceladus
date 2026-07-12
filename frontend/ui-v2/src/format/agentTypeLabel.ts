import type { AgentType } from '../api/coordination'

/**
 * Secondary agent-type metadata for session cards (ENC-TSK-M97 / FTR-130 UAT #1).
 * Always leads with the governed ENC-AGT-* id from the sessions API payload;
 * appends the agent-types roster surface/model label when the roster resolves.
 * Never substitutes runtime/surface tokens when the id or roster row is missing.
 */
export function formatAgentTypeSecondary(
  agentTypeId: string,
  agentType?: AgentType,
): string {
  const id = agentTypeId.trim()
  if (!id) return '—'

  if (agentType?.agent_type_id === id) {
    const surface = agentType.surface?.trim()
    const model = agentType.model?.trim()
    const label = [surface, model].filter(Boolean).join(' / ')
    return label ? `${id} · ${label}` : id
  }

  return id
}

/** Join agent-type metadata with the unchanged runtime line from the API payload. */
export function formatSessionCardDescription(
  agentTypeId: string,
  runtime: string | undefined,
  agentType?: AgentType,
): string | undefined {
  const parts = [formatAgentTypeSecondary(agentTypeId, agentType)]
  const runtimeLine = runtime?.trim()
  if (runtimeLine) parts.push(`Runtime: ${runtimeLine}`)
  return parts.join(' · ')
}
