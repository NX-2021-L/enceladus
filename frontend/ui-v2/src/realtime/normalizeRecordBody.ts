import type { RecordType } from '../types/records'

/**
 * ENC-TSK-T30 (ENC-ISS-926): fields the detail API adds on read that the
 * /records/{recordId} realtime body does not carry.
 *
 * The realtime body is the raw DynamoDB stream image
 * (appsync_feed_publisher build_full_record_body). GET /{project}/{type}/{id}
 * (tracker_mutation _handle_get_record) returns the same item plus the
 * `{type}_id` alias and the record extensions below. Writing the raw image
 * over the cached detail body left `issue_id` / `task_id` / ... undefined, and
 * the page threw on the next render (RecordLink -> resolveRecordTarget).
 */
export const DETAIL_ONLY_KEYS = ['typed_relationships', 'context_node'] as const

type Body = Record<string, unknown>

const isObject = (v: unknown): v is Body => typeof v === 'object' && v !== null && !Array.isArray(v)

const nonEmptyString = (v: unknown): v is string => typeof v === 'string' && v.trim() !== ''

/**
 * Return the realtime body in the detail API's shape: `{type}_id` is set
 * (from the body, else `item_id`, else the route id), and the extension keys
 * the event cannot carry are kept from the cached body. Every other field
 * comes from the event, which is the newer server state.
 */
export function normalizeRecordBody(
  recordType: Exclude<RecordType, 'document'>,
  recordId: string,
  incoming: Body,
  cached: unknown,
): Body {
  const idKey = `${recordType}_id`
  const out: Body = { ...incoming }
  if (isObject(cached)) {
    for (const key of DETAIL_ONLY_KEYS) {
      if (!(key in out) && key in cached) out[key] = cached[key]
    }
  }
  if (!nonEmptyString(out[idKey])) {
    out[idKey] = nonEmptyString(incoming.item_id) ? incoming.item_id : recordId
  }
  return out
}
