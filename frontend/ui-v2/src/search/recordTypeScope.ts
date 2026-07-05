import type { RecordType } from '../types/records'

/**
 * ENC-TSK-L32: reciprocal type-scoping helpers shared by the Feed page
 * (search excludes documents) and the Docs page (search includes ONLY
 * documents). Kept generic over any row shape carrying `recordType` so the
 * same helpers work for `LocalSearchRecord`, `SearchResultHit`, and raw
 * cache-index suggestion rows.
 */

export function excludeRecordType<T extends { recordType: RecordType }>(
  rows: T[],
  excluded: RecordType,
): T[] {
  return rows.filter((row) => row.recordType !== excluded)
}

export function onlyRecordType<T extends { recordType: RecordType }>(
  rows: T[],
  only: RecordType,
): T[] {
  return rows.filter((row) => row.recordType === only)
}
