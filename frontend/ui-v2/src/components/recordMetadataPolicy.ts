/**
 * recordMetadataPolicy.ts -- field policy table for the "Edit metadata" panel (ENC-TSK-R82-0E, FTR-148 AC-2).
 *
 * One row per metadata attribute per record type. `edit` fields are written through the existing governed
 * PATCH {field, value} path (api/mutations.ts setField, If-Match = sync_version); `readonly` fields are shown
 * disabled. Lifecycle fields (status, transition_type, checkout) are deliberately readonly: lifecycle stays on
 * the checkout tools / transition controls, never on this panel. No API default response shape is changed.
 */
import type { ActionContract, FieldPolicy } from '@io-kit/schema_form'

export type MetadataRecordType = 'task' | 'issue' | 'feature' | 'plan'
export type FieldMode = 'edit' | 'readonly'

export interface MetadataField {
  name: string
  label: string
  mode: FieldMode
  kind: 'text' | 'textarea' | 'enum'
  options?: readonly string[]
}

const PRIORITY = ['P0', 'P1', 'P2', 'P3'] as const
const SEVERITY = ['low', 'medium', 'high', 'critical'] as const

const COMMON_READONLY: MetadataField[] = [
  { name: 'status', label: 'Status (lifecycle: use transition controls)', mode: 'readonly', kind: 'text' },
  { name: 'project_id', label: 'Project', mode: 'readonly', kind: 'text' },
  { name: 'created_at', label: 'Created', mode: 'readonly', kind: 'text' },
  { name: 'updated_at', label: 'Updated', mode: 'readonly', kind: 'text' },
]

export const METADATA_POLICY: Record<MetadataRecordType, MetadataField[]> = {
  task: [
    { name: 'title', label: 'Title', mode: 'edit', kind: 'text' },
    { name: 'description', label: 'Description', mode: 'edit', kind: 'textarea' },
    { name: 'priority', label: 'Priority', mode: 'edit', kind: 'enum', options: PRIORITY },
    { name: 'assigned_to', label: 'Assigned to', mode: 'edit', kind: 'text' },
    { name: 'transition_type', label: 'Transition type (immutable)', mode: 'readonly', kind: 'text' },
    ...COMMON_READONLY,
  ],
  issue: [
    { name: 'title', label: 'Title', mode: 'edit', kind: 'text' },
    { name: 'description', label: 'Description', mode: 'edit', kind: 'textarea' },
    { name: 'priority', label: 'Priority', mode: 'edit', kind: 'enum', options: PRIORITY },
    { name: 'severity', label: 'Severity', mode: 'edit', kind: 'enum', options: SEVERITY },
    { name: 'category', label: 'Category', mode: 'edit', kind: 'text' },
    { name: 'hypothesis', label: 'Hypothesis', mode: 'edit', kind: 'textarea' },
    ...COMMON_READONLY,
  ],
  feature: [
    { name: 'title', label: 'Title', mode: 'edit', kind: 'text' },
    { name: 'description', label: 'Description', mode: 'edit', kind: 'textarea' },
    { name: 'category', label: 'Category', mode: 'edit', kind: 'text' },
    { name: 'user_story', label: 'User story', mode: 'edit', kind: 'textarea' },
    ...COMMON_READONLY,
  ],
  plan: [
    { name: 'title', label: 'Title', mode: 'edit', kind: 'text' },
    { name: 'description', label: 'Description', mode: 'edit', kind: 'textarea' },
    { name: 'intent', label: 'Intent', mode: 'edit', kind: 'textarea' },
    { name: 'priority', label: 'Priority', mode: 'edit', kind: 'enum', options: PRIORITY },
    { name: 'category', label: 'Category', mode: 'edit', kind: 'text' },
    ...COMMON_READONLY,
  ],
}

/** Synthetic ActionContract so @io-kit/schema_form renders the widgets; submit is wired by the panel, not an action. */
export function buildMetadataContract(recordType: MetadataRecordType): ActionContract {
  const fields = METADATA_POLICY[recordType]
  const properties: Record<string, unknown> = {}
  fields.forEach((f, i) => {
    const node: Record<string, unknown> = { type: 'string', title: f.label, 'x-io-order': i }
    if (f.kind === 'textarea') node['x-io-widget'] = 'textarea'
    if (f.kind === 'enum') node.enum = [...(f.options ?? [])]
    if (f.name === 'title') node.minLength = 1
    properties[f.name] = node
  })
  return {
    surface: 'enceladus_v2',
    action: `record.metadata.${recordType}`,
    title: `Edit ${recordType} metadata`,
    inputSchema: { type: 'object', properties, required: ['title'] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    schemaSource: 'derived',
    schemaHash: `local:${recordType}:v1`,
    requiresGovernanceHash: false,
    dryRun: false,
    trust: 'first-party',
  }
}

export function metadataFieldPolicy(recordType: MetadataRecordType) {
  const byPointer = new Map(METADATA_POLICY[recordType].map((f) => [`/${f.name}`, f.mode]))
  return (pointer: string): FieldPolicy => {
    const mode = byPointer.get(pointer)
    if (mode === 'edit') return 'show'
    return mode === 'readonly' ? 'readonly' : 'hide'
  }
}

export function metadataInitialValues(recordType: MetadataRecordType, record: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const f of METADATA_POLICY[recordType]) {
    const v = record[f.name]
    out[f.name] = v === null || v === undefined ? '' : String(v)
  }
  return out
}

/** Only `edit` fields whose value changed; the panel PATCHes each one through the governed path. */
export function changedEditableFields(
  recordType: MetadataRecordType,
  initial: Record<string, string>,
  next: Record<string, unknown>,
): Array<{ field: string; value: string }> {
  const out: Array<{ field: string; value: string }> = []
  for (const f of METADATA_POLICY[recordType]) {
    if (f.mode !== 'edit') continue
    const v = next[f.name]
    const s = v === null || v === undefined ? '' : String(v)
    if (s !== (initial[f.name] ?? '')) out.push({ field: f.name, value: s })
  }
  return out
}
