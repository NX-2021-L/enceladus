import { useRef, useState } from 'react'
import { SchemaForm } from '@io-kit/schema_form'
import { useRecordMutation } from '../hooks/useRecordMutation'
import { isRevisionConflictError } from '../api/mutations'
import {
  buildMetadataContract,
  changedEditableFields,
  metadataFieldPolicy,
  metadataInitialValues,
  type MetadataRecordType,
} from './recordMetadataPolicy'

// Module-level caches keep the contract/policy identities stable across renders (React Compiler forbids useMemo).
const contracts = new Map<MetadataRecordType, ReturnType<typeof buildMetadataContract>>()
const policies = new Map<MetadataRecordType, ReturnType<typeof metadataFieldPolicy>>()
function cachedContract(t: MetadataRecordType) {
  if (!contracts.has(t)) contracts.set(t, buildMetadataContract(t))
  return contracts.get(t)!
}
function cachedPolicy(t: MetadataRecordType) {
  if (!policies.has(t)) policies.set(t, metadataFieldPolicy(t))
  return policies.get(t)!
}

/**
 * Edit metadata panel (ENC-TSK-R82-0E, FTR-148 AC-2). @io-kit/schema_form widgets over the field policy table;
 * every changed field is written through the same governed useRecordMutation -> PATCH {field,value} path the
 * cockpit uses (If-Match = sync_version; a 409 opens the shared revision-conflict merge dialog).
 */
export function RecordMetadataPanel({
  projectId,
  recordType,
  recordId,
  record,
  syncVersion,
}: {
  projectId: string
  recordType: MetadataRecordType
  recordId: string
  record: Record<string, unknown>
  syncVersion?: number
}) {
  const mutation = useRecordMutation()
  const contract = cachedContract(recordType)
  const fieldPolicy = cachedPolicy(recordType)
  const initial = metadataInitialValues(recordType, record)
  const revision = useRef<number | undefined>(syncVersion)
  const [status, setStatus] = useState<{ kind: 'ok' | 'error'; message: string } | null>(null)
  const [saving, setSaving] = useState(false)

  async function save(args: unknown) {
    const changes = changedEditableFields(recordType, initial, (args ?? {}) as Record<string, unknown>)
    if (changes.length === 0) {
      setStatus({ kind: 'ok', message: 'No changes to save.' })
      return
    }
    setSaving(true)
    setStatus(null)
    revision.current = syncVersion
    try {
      for (const c of changes) {
        const res = await mutation.mutateAsync({
          projectId,
          recordType,
          recordId,
          action: 'set_field',
          field: c.field,
          value: c.value,
          syncVersion: revision.current,
        })
        revision.current = res.sync_version ?? revision.current
      }
      setStatus({
        kind: 'ok',
        message: `Saved ${changes.map((c) => c.field).join(', ')}${revision.current !== undefined ? ` (version ${revision.current})` : ''}.`,
      })
    } catch (e) {
      setStatus({
        kind: 'error',
        message: isRevisionConflictError(e)
          ? 'This record changed since you opened it. Resolve in the conflict dialog, then re-apply your edit.'
          : e instanceof Error
            ? e.message
            : 'Save failed.',
      })
    } finally {
      setSaving(false)
    }
  }

  return (
    <section aria-label="Edit metadata" data-testid="record-metadata-panel">
      <p>Editable fields write through the governed tracker path. Status and lifecycle stay on the transition controls.</p>
      <SchemaForm
        key={`${recordId}:${syncVersion ?? 'x'}`}
        contract={contract}
        initialValues={initial}
        fieldPolicy={fieldPolicy}
        submitLabel={saving ? 'Saving…' : 'Save metadata'}
        onSubmit={(args) => void save(args)}
        idPrefix={`meta-${recordId}`}
      />
      {status ? <p role={status.kind === 'error' ? 'alert' : 'status'}>{status.message}</p> : null}
    </section>
  )
}
