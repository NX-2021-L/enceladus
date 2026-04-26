/**
 * Unit tests for recordNormalizers (ENC-FTR-073 Phase 2b / ENC-TSK-D95).
 *
 * Fixtures are derived from the representative API payloads documented in
 * DOC-BB658D8644DF §3 (live samples captured during Phase 1 discovery). Each
 * normalizer is exercised against:
 *   - a realistic raw tracker-API payload with the fields a live record
 *     actually carries
 *   - a minimal/partial payload (missing optional fields) to verify safe
 *     defaults
 *   - a malformed/empty payload to verify the no-throw contract
 *
 * Critical cross-cuts verified per the design contract:
 *   - item_id -> {type}_id rename
 *   - acceptance_criteria / evidence / pillar_scores / objectives_set shapes
 *   - lesson `extensions` non-trivial remap: author -> provider, content ->
 *     description, evidence_ids dropped
 *   - missing-array defaults flatten to [] (not undefined)
 *   - empty-string checkout fields coerce to null
 */

import { describe, expect, it } from 'vitest'
import {
  normalizeDocument,
  normalizeFeature,
  normalizeIssue,
  normalizeLesson,
  normalizePlan,
  normalizeRecord,
  normalizeTask,
} from './recordNormalizers'

describe('normalizeTask', () => {
  it('renames item_id to task_id and preserves the feed-shape scalar set', () => {
    const raw = {
      item_id: 'ENC-TSK-C08',
      record_id: 'task#ENC-TSK-C08',
      record_type: 'task',
      project_id: 'enceladus',
      title: 'Task title',
      description: 'Body',
      status: 'in-progress',
      priority: 'P1',
      category: 'implementation',
      intent: 'ship it',
      created_at: '2026-03-01T00:00:00Z',
      updated_at: '2026-03-02T00:00:00Z',
      acceptance_criteria: [
        { description: 'AC1', evidence: '', evidence_acceptance: false },
      ],
      coordination: false,
      active_agent_session: true,
      active_agent_session_id: 'sess-1',
      active_agent_session_parent: false,
      related_feature_ids: ['ENC-FTR-073'],
      related_plan_ids: ['ENC-PLN-025'],
      checkout_state: 'checked_out',
      transition_type: 'web_deploy',
      components: ['comp-enceladus-pwa'],
      subtask_ids: ['ENC-TSK-D94'],
    }
    const { data, warning } = normalizeTask(raw)
    expect(warning).toBeUndefined()
    expect(data.task_id).toBe('ENC-TSK-C08')
    // record_id / record_type / related_plan_ids must not bleed onto the
    // feed-shape Task interface.
    expect((data as unknown as Record<string, unknown>).record_id).toBeUndefined()
    expect(data.transition_type).toBe('web_deploy')
    expect(data.checkout_state).toBe('checked_out')
    expect(data.active_agent_session).toBe(true)
    expect(data.acceptance_criteria).toHaveLength(1)
    expect(data.related_feature_ids).toEqual(['ENC-FTR-073'])
    expect(data.subtask_ids).toEqual(['ENC-TSK-D94'])
  })

  it('coerces empty-string checkout fields to null (feed parity)', () => {
    const { data } = normalizeTask({ item_id: 'ENC-TSK-1', checked_out_by: '', checked_out_at: '' })
    expect(data.checked_out_by).toBeNull()
    expect(data.checked_out_at).toBeNull()
  })

  it('fills default arrays and defaults status/priority for minimal payloads', () => {
    const { data } = normalizeTask({ item_id: 'ENC-TSK-2', project_id: 'enceladus' })
    expect(data.task_id).toBe('ENC-TSK-2')
    expect(data.status).toBe('open')
    expect(data.priority).toBe('P2')
    expect(data.related_feature_ids).toEqual([])
    expect(data.related_task_ids).toEqual([])
    expect(data.history).toEqual([])
    expect(data.acceptance_criteria).toEqual([])
    expect(data.typed_relationships).toEqual([])
    expect(data.context_node).toBeUndefined()
  })

  it('emits a warning and never throws when the identifier is missing', () => {
    const { data, warning } = normalizeTask({})
    expect(data.task_id).toBe('')
    expect(warning).toContain('task record missing identifier')
  })

  it('tolerates non-object input without throwing', () => {
    expect(() => normalizeTask(null)).not.toThrow()
    expect(() => normalizeTask('not a record')).not.toThrow()
    expect(() => normalizeTask(42)).not.toThrow()
  })
})

describe('normalizeIssue', () => {
  it('renames item_id to issue_id and defaults severity to medium', () => {
    const raw = {
      item_id: 'ENC-ISS-200',
      record_id: 'issue#ENC-ISS-200',
      project_id: 'enceladus',
      title: 'Feed cap regression',
      description: 'Body',
      status: 'open',
      priority: 'P1',
      evidence: [
        {
          description: 'Repro',
          steps_to_duplicate: ['Navigate to plan'],
          observed_by: 'user',
          timestamp: '2026-03-01T00:00:00Z',
        },
      ],
    }
    const { data } = normalizeIssue(raw)
    expect(data.issue_id).toBe('ENC-ISS-200')
    expect(data.severity).toBe('medium')
    expect(data.evidence).toHaveLength(1)
    expect(data.evidence?.[0].steps_to_duplicate).toEqual(['Navigate to plan'])
  })

  it('preserves severity when provided', () => {
    const { data } = normalizeIssue({ item_id: 'ENC-ISS-1', severity: 'high' })
    expect(data.severity).toBe('high')
  })
})

describe('normalizeFeature', () => {
  it('renames item_id, fills success_metrics / owners arrays, preserves acceptance_criteria', () => {
    const raw = {
      item_id: 'ENC-FTR-073',
      record_id: 'feature#ENC-FTR-073',
      project_id: 'enceladus',
      title: 'PWA direct-API fallback',
      description: 'Body',
      status: 'in-progress',
      user_story: 'As a user...',
      acceptance_criteria: [
        { description: 'AC1', evidence: '', evidence_acceptance: false },
      ],
    }
    const { data } = normalizeFeature(raw)
    expect(data.feature_id).toBe('ENC-FTR-073')
    expect(data.owners).toEqual([])
    expect(data.success_metrics).toEqual([])
    expect(data.success_metrics_count).toBe(0)
    expect(data.acceptance_criteria).toHaveLength(1)
  })

  it('derives success_metrics_count from array length when omitted', () => {
    const { data } = normalizeFeature({
      item_id: 'ENC-FTR-1',
      success_metrics: ['m1', 'm2', 'm3'],
    })
    expect(data.success_metrics_count).toBe(3)
  })
})

describe('normalizePlan', () => {
  it('renames item_id to plan_id and preserves objectives/attached_documents', () => {
    const raw = {
      item_id: 'ENC-PLN-006',
      record_id: 'plan#ENC-PLN-006',
      project_id: 'enceladus',
      title: 'Plan title',
      description: 'Body',
      status: 'started',
      priority: 'P0',
      objectives_set: ['ENC-TSK-1', 'ENC-TSK-2'],
      attached_documents: ['DOC-ABC'],
      related_feature_id: 'ENC-FTR-073',
      checkout_state: '',
      checked_out_by: '',
      checked_out_at: '',
    }
    const { data } = normalizePlan(raw)
    expect(data.plan_id).toBe('ENC-PLN-006')
    expect(data.status).toBe('started')
    expect(data.priority).toBe('P0')
    expect(data.objectives_set).toEqual(['ENC-TSK-1', 'ENC-TSK-2'])
    expect(data.attached_documents).toEqual(['DOC-ABC'])
    expect(data.related_feature_id).toBe('ENC-FTR-073')
    // Empty-string checkout fields must collapse to null (design §4).
    expect(data.checkout_state).toBeNull()
    expect(data.checked_out_by).toBeNull()
    expect(data.checked_out_at).toBeNull()
  })

  it('defaults status drafted, priority P2 for minimal payloads', () => {
    const { data } = normalizePlan({ item_id: 'ENC-PLN-1' })
    expect(data.status).toBe('drafted')
    expect(data.priority).toBe('P2')
    expect(data.category).toBeNull()
    expect(data.objectives_set).toEqual([])
  })
})

describe('normalizeLesson', () => {
  it('remaps API-shape extensions (author/content) to feed shape (provider/description)', () => {
    // From DOC-BB658D8644DF §3.5 — real API response for ENC-LSN-001
    const raw = {
      item_id: 'ENC-LSN-001',
      record_id: 'lesson#ENC-LSN-001',
      project_id: 'enceladus',
      title: 'Lesson',
      observation: 'obs',
      insight: 'insight',
      evidence_chain: ['E1', 'E2'],
      provenance: 'pro',
      confidence: 0.9,
      pillar_scores: {
        efficiency: 0.8,
        alignment: 0.7,
        human_protection: 0.9,
        intention: 0.85,
      },
      resonance_score: 0.88,
      pillar_composite: 0.82,
      extensions: [
        {
          evidence_ids: ['E1'],
          author: 'analysis-lead',
          content: 'Extension observation',
          timestamp: '2026-03-01T00:00:00Z',
        },
      ],
      lesson_version: 2,
      category: 'governance',
      status: 'active',
      related_task_ids: ['ENC-TSK-1'],
    }
    const { data } = normalizeLesson(raw)
    expect(data.lesson_id).toBe('ENC-LSN-001')
    expect(data.extensions).toHaveLength(1)
    const ext = data.extensions[0]
    expect(ext.description).toBe('Extension observation')
    expect(ext.provider).toBe('analysis-lead')
    expect(ext.timestamp).toBe('2026-03-01T00:00:00Z')
    // evidence_ids must be dropped per the Phase 1 contract.
    expect((ext as unknown as Record<string, unknown>).evidence_ids).toBeUndefined()
    // pillar_scores float pass-through
    expect(data.pillar_scores.alignment).toBe(0.7)
    expect(data.resonance_score).toBe(0.88)
    expect(data.lesson_version).toBe(2)
  })

  it('accepts already-feed-shape extensions (provider/description) idempotently', () => {
    const { data } = normalizeLesson({
      item_id: 'ENC-LSN-2',
      extensions: [{ description: 'feed shape', provider: 'feed', timestamp: '2026-01-01' }],
    })
    expect(data.extensions[0].description).toBe('feed shape')
    expect(data.extensions[0].provider).toBe('feed')
  })

  it('fills pillar_scores with zero defaults when missing', () => {
    const { data } = normalizeLesson({ item_id: 'ENC-LSN-3' })
    expect(data.pillar_scores).toEqual({
      efficiency: 0,
      alignment: 0,
      human_protection: 0,
      intention: 0,
    })
    expect(data.lesson_version).toBe(1)
    expect(data.status).toBe('active')
  })
})

describe('normalizeDocument', () => {
  it('produces a feed-shape Document that is behaviorally indistinguishable from the live document_api payload', () => {
    // From DOC-BB658D8644DF §3.6 — documents are already feed-shape; this is
    // the identity contract.
    const raw = {
      document_id: 'DOC-FFB4C9D87BCC',
      project_id: 'enceladus',
      title: 'Title',
      description: 'Desc',
      file_name: 'file.md',
      content_type: 'text/markdown',
      content_hash: 'abc',
      size_bytes: 1000,
      keywords: ['k1'],
      related_items: ['ENC-TSK-D89'],
      status: 'active',
      created_by: 'internal-key',
      created_at: '2026-03-01T00:00:00Z',
      updated_at: '2026-03-02T00:00:00Z',
      version: 9,
      content: '# Title',
    }
    const { data } = normalizeDocument(raw)
    expect(data.document_id).toBe('DOC-FFB4C9D87BCC')
    expect(data.size_bytes).toBe(1000)
    expect(data.version).toBe(9)
    expect(data.content).toBe('# Title')
    expect(data.keywords).toEqual(['k1'])
  })

  it('defaults status to active and version to 1 when missing', () => {
    const { data, warning } = normalizeDocument({})
    expect(data.document_id).toBe('')
    expect(data.status).toBe('active')
    expect(data.version).toBe(1)
    expect(warning).toContain('document record missing identifier')
  })
})

describe('normalizeRecord dispatch', () => {
  it('dispatches to the correct normalizer by recordType', () => {
    const { data: task } = normalizeRecord('task', { item_id: 'ENC-TSK-X' })
    expect(task.task_id).toBe('ENC-TSK-X')

    const { data: lesson } = normalizeRecord('lesson', {
      item_id: 'ENC-LSN-X',
      extensions: [{ author: 'a', content: 'c', timestamp: 't' }],
    })
    expect(lesson.extensions[0].provider).toBe('a')
    expect(lesson.extensions[0].description).toBe('c')
  })
})
