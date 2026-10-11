import type { PropertyDef } from '@io-kit/search'
import { buildAttributeRegistry } from './attributeRegistry'

/**
 * DVP-TSK-995: the kit PropertyDefs for the enceladus corpus (design section 4). The governed filter keys come from
 * the existing attribute registry; `record_id` is exposed as `id` (old links that say `record_id` are re-keyed in
 * feedUrl.ts). Enum values are suggested from the local corpus facets, so suggestion is instant.
 */
const REGISTRY_ALIAS: Record<string, string> = { record_id: 'id' }
const EXTRA_KEYS = ['category', 'components', 'tags', 'updated_at', 'created_at']

const BASE: Record<string, Omit<PropertyDef, 'key'>> = {
  record_type: { label: 'Record type', type: 'enum' },
  project_id: { label: 'Project', type: 'enum' },
  status: { label: 'Status', type: 'enum' },
  priority: { label: 'Priority', type: 'enum' },
  category: { label: 'Category', type: 'enum' },
  checkout_state: { label: 'Checkout state', type: 'enum' },
  components: { label: 'Components', type: 'enum' },
  tags: { label: 'Tags', type: 'enum' },
  updated_at: { label: 'Updated', type: 'date', searchable: false },
  created_at: { label: 'Created', type: 'date', searchable: false },
  title: { label: 'Title', type: 'string' },
  id: { label: 'Record ID', type: 'string' },
}

export function buildPropertyDefs(): PropertyDef[] {
  const keys = [...buildAttributeRegistry([]).map((p) => REGISTRY_ALIAS[p.key] ?? p.key), ...EXTRA_KEYS]
  return [...new Set(keys)].filter((k) => BASE[k]).map((key) => ({ key, ...BASE[key]! }))
}

export const ENCELADUS_PROPERTIES: PropertyDef[] = buildPropertyDefs()

/** /docs scope: every document has record_type=document, so that property is not offered there. */
export const DOCS_PROPERTIES: PropertyDef[] = ENCELADUS_PROPERTIES.filter((p) => p.key !== 'record_type')
