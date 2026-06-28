import { describe, it, expect } from 'vitest'
import {
  buildPlanTree,
  buildRelationshipGraph,
  mergeGraphElements,
  type GraphRecordInput,
} from './graphModel'

describe('buildPlanTree (AC-21 PLAN_CONTAINS)', () => {
  it('emits a plan node plus PLAN_CONTAINS edges to every objective', () => {
    const g = buildPlanTree(
      { planId: 'ENC-PLN-006', title: 'v4', objectiveIds: ['ENC-TSK-B59', 'ENC-TSK-C08'] },
    )
    expect(g.nodes.map((n) => n.data.id)).toEqual(['ENC-PLN-006', 'ENC-TSK-B59', 'ENC-TSK-C08'])
    expect(g.edges).toHaveLength(2)
    expect(g.edges.every((e) => e.data.relationship_type === 'PLAN_CONTAINS')).toBe(true)
    expect(g.edges[0].data.label).toBe('PLAN_CONTAINS')
  })

  it('uses provided objective records for labels/status', () => {
    const g = buildPlanTree(
      { planId: 'P1', objectiveIds: ['T1'] },
      [{ recordId: 'T1', title: 'Task one', record_type: 'task', status: 'closed' }],
    )
    const node = g.nodes.find((n) => n.data.id === 'T1')
    expect(node?.data.status).toBe('closed')
    expect(node?.data.label).toContain('Task one')
  })
})

describe('buildRelationshipGraph (AC-22 typed edges + context-node labels)', () => {
  const records: GraphRecordInput[] = [
    {
      recordId: 'ENC-TSK-B67',
      title: 'Cockpit',
      record_type: 'task',
      context_node: {
        freshness_score: 0.9,
        structural_importance: 0.42,
        information_density: 0.5,
        access_frequency: 0,
      },
      typed_relationships: [
        {
          relationship_type: 'INFORMED_BY',
          target_id: 'DOC-E470AC8CE9A8',
          weight: 1,
          confidence: 1,
          reason: null,
          created_at: null,
        },
      ],
    },
  ]

  it('renders the relationship type as the edge label', () => {
    const g = buildRelationshipGraph(records)
    const edge = g.edges[0]
    expect(edge.data.relationship_type).toBe('INFORMED_BY')
    expect(edge.data.label).toContain('INFORMED_BY')
  })

  it('surfaces structural_importance (context-node metadata) in the edge label', () => {
    const g = buildRelationshipGraph(records)
    expect(g.edges[0].data.label).toContain('S=0.42')
  })

  it('carries context-node scores on the node data', () => {
    const g = buildRelationshipGraph(records)
    const node = g.nodes.find((n) => n.data.id === 'ENC-TSK-B67')
    expect(node?.data.context_node?.structural_importance).toBe(0.42)
    expect(node?.data.structural_importance).toBe(0.42)
  })

  it('creates placeholder nodes for edge targets not in the record set', () => {
    const g = buildRelationshipGraph(records)
    expect(g.nodes.some((n) => n.data.id === 'DOC-E470AC8CE9A8')).toBe(true)
  })
})

describe('mergeGraphElements', () => {
  it('de-duplicates nodes and edges by id', () => {
    const a = buildPlanTree({ planId: 'P1', objectiveIds: ['T1'] })
    const b = buildPlanTree({ planId: 'P1', objectiveIds: ['T1'] })
    const merged = mergeGraphElements(a, b)
    expect(merged.nodes).toHaveLength(2)
    expect(merged.edges).toHaveLength(1)
  })
})
