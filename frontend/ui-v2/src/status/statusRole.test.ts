import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import statusMap from '../../../design-system-2/status-map.json'
import {
  STATUS_MAP_VERSION,
  STATUS_ROLES,
  kindStatuses,
  mappedKinds,
  railOverrides,
  railToken,
  roleGlyph,
  statusLabel,
  statusRole,
} from './statusRole'

describe('statusRole: every governed status in status-map.json', () => {
  const kinds = mappedKinds()

  it('reads status-map 2026-11-13.2 with 21 vocabularies and 112 values', () => {
    expect(STATUS_MAP_VERSION).toBe('2026-11-13.2')
    expect(kinds).toHaveLength(21)
    expect(kinds.reduce((n, k) => n + Object.keys(kindStatuses(k)).length, 0)).toBe(112)
  })

  for (const kind of Object.keys(statusMap.kinds)) {
    const table = (statusMap.kinds as Record<string, { statuses: Record<string, string> }>)[kind].statuses
    it(`${kind}: each status maps to the role in the file`, () => {
      for (const [status, role] of Object.entries(table)) {
        expect(statusRole(kind, status), `${kind}.${status}`).toBe(role)
        expect(statusRole(kind, `  ${status.toUpperCase()} `), `${kind}.${status} normalized`).toBe(role)
      }
    })
  }

  it('every role the map uses is one of the nine', () => {
    for (const kind of kinds) for (const role of Object.values(kindStatuses(kind))) expect(STATUS_ROLES).toContain(role)
  })
})

describe('statusRole: the defects the spec closes', () => {
  it('a closed task is done, whatever its priority (priority is not an input)', () => {
    expect(statusRole('task', 'closed')).toBe('done')
  })

  it('open and complete are different roles', () => {
    expect(statusRole('task', 'open')).toBe('todo')
    expect(statusRole('plan', 'complete')).toBe('done')
  })

  it('a task in pr is waiting on a person', () => {
    expect(statusRole('task', 'pr')).toBe('waiting')
  })

  it('lessons show their lifecycle', () => {
    expect(statusRole('lesson', 'draft')).toBe('todo')
    expect(statusRole('lesson', 'proposed')).toBe('waiting')
    expect(statusRole('lesson', 'accepted')).toBe('done')
    expect(statusRole('lesson', 'active')).toBe('live')
    expect(statusRole('lesson', 'superseded')).toBe('retired')
  })

  it('plan incomplete is still in progress', () => {
    expect(statusRole('plan', 'incomplete')).toBe('active')
  })

  it('an escalation waiting on io is waiting; denied is failed; applied is done', () => {
    expect(statusRole('escalation', 'requested')).toBe('waiting')
    expect(statusRole('escalation', 'denied')).toBe('failed')
    expect(statusRole('escalation', 'applied')).toBe('done')
  })
})

describe('statusRole: spelling, kind and fallback', () => {
  it('accepts the underscore spellings the feed delivers, inside the kind table', () => {
    expect(statusRole('task', 'in_progress')).toBe('active')
    expect(statusRole('task', 'merged_main')).toBe('active')
    expect(statusRole('task', 'deploy_success')).toBe('active')
    expect(statusRole('task', 'coding_updates')).toBe('caution')
  })

  it('accepts the hyphen spelling of an underscore status, inside the kind table', () => {
    expect(statusRole('escalation', 'denied-with-guidance')).toBe('failed')
    expect(statusRole('coordination_request', 'dead-letter')).toBe('failed')
  })

  it('resolves kind aliases the app uses', () => {
    expect(statusRole('session', 'claimed')).toBe('active')
    expect(statusRole('coordination', 'dead_letter')).toBe('failed')
    expect(statusRole('lesson-candidate', 'pending')).toBe('waiting')
  })

  it('uses the kind for strings that differ by kind', () => {
    expect(statusRole('escalation', 'approved')).toBe('active')
    expect(statusRole('lesson_candidate', 'approved')).toBe('done')
    expect(statusRole('handoff', 'pending')).toBe('todo')
    expect(statusRole('gate', 'pending')).toBe('waiting')
    expect(statusRole('deployment_decision', 'deployed')).toBe('done')
    expect(statusRole('task', 'deployed')).toBe('active')
  })

  it('without a kind, an ambiguous string takes the first role the map lists', () => {
    expect(statusRole(undefined, 'approved')).toBe((statusMap.ambiguous_without_kind as Record<string, string[]>).approved[0])
  })

  it('falls back to the any table, then legacy aliases', () => {
    expect(statusRole('document', 'active')).toBe('live')
    expect(statusRole(undefined, 'blocked')).toBe('waiting')
    expect(statusRole('task', 'blocked')).toBe('waiting')
    expect(statusRole(undefined, 'error')).toBe('failed')
  })

  it('anything unmapped is unknown, never a guess', () => {
    expect(statusRole('task', 'teleported')).toBe('unknown')
    expect(statusRole('task', '')).toBe('unknown')
    expect(statusRole('task', undefined)).toBe('unknown')
    expect(statusRole(undefined, null)).toBe('unknown')
  })
})

describe('labels, glyphs and the rail', () => {
  it('labels show separators as spaces', () => {
    expect(statusLabel('merged_main')).toBe('merged main')
    expect(statusLabel('deploy-success')).toBe('deploy success')
  })

  it('every role has a distinct glyph', () => {
    const glyphs = STATUS_ROLES.map(roleGlyph)
    expect(new Set(glyphs).size).toBe(STATUS_ROLES.length)
  })

  it('the rail shows record type unless the role is caution, waiting or failed', () => {
    expect(railToken('task', 'done')).toBe('rail-task')
    expect(railToken('plan', 'active')).toBe('rail-plan')
    expect(railToken('lesson', 'live')).toBe('rail-lesson')
    expect(railToken('document', 'live')).toBe('rail-document')
    expect(railToken('widget', 'todo')).toBe('rail-default')
    expect(railToken('task', 'waiting')).toBe('status-waiting-rail')
    expect(railToken('lesson', 'caution')).toBe('status-caution-rail')
    expect(railToken('plan', 'failed')).toBe('status-failed-rail')
    expect(railOverrides('waiting')).toBe(true)
    expect(railOverrides('done')).toBe(false)
  })
})

// Report-only: governed status enums the map does not list. Never fails the build.
describe('governance dictionary coverage (report only)', () => {
  it('lists dictionary status values that have no map entry', () => {
    const here = dirname(fileURLToPath(import.meta.url))
    const path = resolve(here, '../../../../backend/lambda/coordination_api/governance_data_dictionary.json')
    let entities: Record<string, { fields?: Record<string, { enum?: string[] }> }> = {}
    try {
      entities = JSON.parse(readFileSync(path, 'utf8')).entities
    } catch {
      console.info('[status coverage] dictionary not readable from', path)
      return
    }
    const missing: string[] = []
    for (const [kind, def] of Object.entries(statusMap.kinds as Record<string, { dictionary: string }>)) {
      const parts = def.dictionary.split('.')
      const values = entities[parts.slice(0, -1).join('.')]?.fields?.[parts[parts.length - 1]]?.enum
      for (const v of values ?? []) if (statusRole(kind, v) === 'unknown') missing.push(`${kind}.${v}`)
    }
    if (missing.length) console.info('[status coverage] unmapped dictionary values:', missing.join(', '))
    expect(Array.isArray(missing)).toBe(true)
  })
})
