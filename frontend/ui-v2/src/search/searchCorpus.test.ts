/**
 * ENC-TSK-P60 — corpus rows carry governed metadata, never event actions.
 *
 * ENC-ISS-719: `buildSearchCorpus` used to map the event ACTION ("updated")
 * into `status`, painting every plan/lesson card with an UPDATED chip and
 * breaking Last-Updated sort. ENC-ISS-718: the Feed's merge REPLACED warm
 * cache rows with these thin event rows, losing priority/updatedAt for any
 * record that appeared in the realtime stream.
 */
import { describe, expect, it } from 'vitest'
import { buildSearchCorpus, mergeEventRowOntoCache } from './searchCorpus'
import type { FeedRealtimeEvent } from '../types/feedEvents'
import type { LocalSearchRecord } from '../types/search'
import type { ProjectSummary } from '../api/projects'

const PROJECTS: ProjectSummary[] = [{ project_id: 'enceladus', prefix: 'ENC' }]

function event(partial: Partial<FeedRealtimeEvent> & { recordId: string }): FeedRealtimeEvent {
  return {
    eventId: `evt-${partial.recordId}`,
    record_type: 'plan',
    action: 'updated',
    actorType: 'agent',
    actorId: 'feed-snapshot',
    summary: `${partial.recordId}: title`,
    cursor: 1,
    channels: ['/feed/updates'],
    ...partial,
  }
}

describe('buildSearchCorpus (ENC-TSK-P60)', () => {
  it('never uses the event action as a lifecycle status', () => {
    const rows = buildSearchCorpus([event({ recordId: 'ENC-PLN-090' })], PROJECTS)
    expect(rows[0].status).toBeUndefined()
    expect(rows[0].status).not.toBe('updated')
  })

  it('uses the governed status/title/updated_at the snapshot row carries', () => {
    const rows = buildSearchCorpus(
      [
        event({
          recordId: 'ENC-PLN-090',
          recordStatus: 'started',
          recordTitle: 'v4 UI UAT Remediation',
          recordUpdatedAt: '2026-08-27T01:24:55Z',
          recordPriority: 'P0',
        }),
      ],
      PROJECTS,
    )
    expect(rows[0]).toMatchObject({
      status: 'started',
      title: 'v4 UI UAT Remediation',
      updatedAt: '2026-08-27T01:24:55Z',
      priority: 'P0',
    })
  })

  it('prefers the full record body over snapshot metadata when present', () => {
    const rows = buildSearchCorpus(
      [
        event({
          recordId: 'ENC-TSK-P55',
          record_type: 'task',
          recordStatus: 'open',
          record: { status: 'in-progress', priority: 'P1', updated_at: '2026-08-27T02:00:00Z' },
        }),
      ],
      PROJECTS,
    )
    expect(rows[0].status).toBe('in-progress')
    expect(rows[0].priority).toBe('P1')
    expect(rows[0].updatedAt).toBe('2026-08-27T02:00:00Z')
  })
})

describe('mergeEventRowOntoCache (ENC-TSK-P60)', () => {
  const cacheRow: LocalSearchRecord = {
    recordId: 'ENC-PLN-090',
    recordType: 'plan',
    projectId: 'enceladus',
    title: 'v4 UI UAT Remediation',
    status: 'started',
    priority: 'P0',
    updatedAt: '2026-08-27T01:00:00Z',
  }

  it('keeps governed cache metadata when the event row has none', () => {
    const eventRow: LocalSearchRecord = {
      recordId: 'ENC-PLN-090',
      recordType: 'plan',
      projectId: 'enceladus',
      title: 'ENC-PLN-090: v4 UI UAT Remediation',
    }
    const merged = mergeEventRowOntoCache(cacheRow, eventRow)
    expect(merged.status).toBe('started')
    expect(merged.priority).toBe('P0')
    expect(merged.updatedAt).toBe('2026-08-27T01:00:00Z')
    expect(merged.title).toBe('v4 UI UAT Remediation')
  })

  it('takes fresher event fields when the event truly carries them', () => {
    const eventRow: LocalSearchRecord = {
      recordId: 'ENC-PLN-090',
      recordType: 'plan',
      projectId: 'enceladus',
      title: 'whatever',
      status: 'complete',
      updatedAt: '2026-08-27T03:00:00Z',
    }
    const merged = mergeEventRowOntoCache(cacheRow, eventRow)
    expect(merged.status).toBe('complete')
    expect(merged.updatedAt).toBe('2026-08-27T03:00:00Z')
    expect(merged.priority).toBe('P0')
  })

  it('never regresses updatedAt to an older event timestamp', () => {
    const eventRow: LocalSearchRecord = {
      recordId: 'ENC-PLN-090',
      recordType: 'plan',
      projectId: 'enceladus',
      title: 'whatever',
      updatedAt: '2026-08-26T00:00:00Z',
    }
    expect(mergeEventRowOntoCache(cacheRow, eventRow).updatedAt).toBe('2026-08-27T01:00:00Z')
  })
})
