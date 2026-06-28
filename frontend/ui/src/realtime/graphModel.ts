/**
 * Graph explorer model builder (ENC-TSK-B67 AC-21, AC-22).
 *
 * Pure, framework-free transform from governed records + typed relationships +
 * context-node scores into Cytoscape.js element descriptors. Keeping the data
 * transform separate from the canvas component makes the plan-tree (AC-21) and
 * typed-relationship + context-node-edge-label (AC-22) logic unit-testable
 * without a DOM/WebGL context.
 *
 * AC-21: PLAN_CONTAINS edges connect a plan to each objective task.
 * AC-22: typed-relationship edges (INFORMED_BY, LEARNED_FROM, RELATED_TO,
 *        PLAN_CONTAINS, BELONGS_TO, + custom dictionary types) render with the
 *        relationship_type as the edge label; context-node scores render as node
 *        metadata AND as edge labels (structural_importance on the edge).
 */

import type { ContextNodeMeta, TypedRelationshipEdge } from '../types/feeds'

export interface CyNodeData {
  id: string
  label: string
  record_type: string
  status?: string
  context_node?: ContextNodeMeta
  /** Convenience: structural_importance surfaced for node sizing/labels. */
  structural_importance?: number
}

export interface CyEdgeData {
  id: string
  source: string
  target: string
  /** Edge label rendered in the graph (relationship type, AC-22). */
  label: string
  relationship_type: string
  weight?: number
  confidence?: number
}

export interface CyElement<T> {
  data: T
}

export interface GraphElements {
  nodes: CyElement<CyNodeData>[]
  edges: CyElement<CyEdgeData>[]
}

export interface GraphRecordInput {
  recordId: string
  title?: string
  record_type: string
  status?: string
  context_node?: ContextNodeMeta
  typed_relationships?: TypedRelationshipEdge[]
}

export interface PlanInput {
  planId: string
  title?: string
  status?: string
  /** Objective task IDs (PLAN_CONTAINS targets, AC-21). */
  objectiveIds: string[]
  context_node?: ContextNodeMeta
}

function nodeFromRecord(rec: GraphRecordInput): CyElement<CyNodeData> {
  return {
    data: {
      id: rec.recordId,
      label: rec.title ? `${rec.recordId}\n${rec.title}` : rec.recordId,
      record_type: rec.record_type,
      status: rec.status,
      context_node: rec.context_node,
      structural_importance: rec.context_node?.structural_importance,
    },
  }
}

/**
 * Build PLAN_CONTAINS plan-tree elements (AC-21): the plan node plus one
 * PLAN_CONTAINS edge to each objective task. Objective nodes are emitted as
 * lightweight placeholders if not present in `objectiveRecords`.
 */
export function buildPlanTree(
  plan: PlanInput,
  objectiveRecords: GraphRecordInput[] = [],
): GraphElements {
  const byId = new Map(objectiveRecords.map((r) => [r.recordId, r]))
  const nodes: CyElement<CyNodeData>[] = [
    {
      data: {
        id: plan.planId,
        label: plan.title ? `${plan.planId}\n${plan.title}` : plan.planId,
        record_type: 'plan',
        status: plan.status,
        context_node: plan.context_node,
        structural_importance: plan.context_node?.structural_importance,
      },
    },
  ]
  const edges: CyElement<CyEdgeData>[] = []

  for (const objId of plan.objectiveIds) {
    const rec = byId.get(objId)
    nodes.push(
      rec
        ? nodeFromRecord(rec)
        : { data: { id: objId, label: objId, record_type: 'task' } },
    )
    edges.push({
      data: {
        id: `${plan.planId}__PLAN_CONTAINS__${objId}`,
        source: plan.planId,
        target: objId,
        label: 'PLAN_CONTAINS',
        relationship_type: 'PLAN_CONTAINS',
      },
    })
  }

  return { nodes, edges }
}

/**
 * Build typed-relationship + context-node graph elements (AC-22) for a set of
 * records. Each record becomes a node carrying its context-node scores; each
 * typed_relationships entry becomes a labeled edge. The edge label combines the
 * relationship type with the source node's structural_importance so context-node
 * metadata is visible as an edge label per AC-22.
 */
export function buildRelationshipGraph(records: GraphRecordInput[]): GraphElements {
  const nodes: CyElement<CyNodeData>[] = []
  const edges: CyElement<CyEdgeData>[] = []
  const nodeIds = new Set<string>()
  const edgeIds = new Set<string>()

  const ensureNode = (rec: GraphRecordInput) => {
    if (nodeIds.has(rec.recordId)) return
    nodeIds.add(rec.recordId)
    nodes.push(nodeFromRecord(rec))
  }

  for (const rec of records) {
    ensureNode(rec)
    for (const edge of rec.typed_relationships ?? []) {
      if (!nodeIds.has(edge.target_id)) {
        nodeIds.add(edge.target_id)
        nodes.push({
          data: { id: edge.target_id, label: edge.target_id, record_type: 'record' },
        })
      }
      const edgeId = `${rec.recordId}__${edge.relationship_type}__${edge.target_id}`
      if (edgeIds.has(edgeId)) continue
      edgeIds.add(edgeId)
      const si = rec.context_node?.structural_importance
      const label =
        si !== undefined
          ? `${edge.relationship_type} · S=${si.toFixed(2)}`
          : edge.relationship_type
      edges.push({
        data: {
          id: edgeId,
          source: rec.recordId,
          target: edge.target_id,
          label,
          relationship_type: edge.relationship_type,
          weight: edge.weight,
          confidence: edge.confidence,
        },
      })
    }
  }

  return { nodes, edges }
}

/** Merge multiple element sets, de-duplicating nodes and edges by id. */
export function mergeGraphElements(...sets: GraphElements[]): GraphElements {
  const nodes = new Map<string, CyElement<CyNodeData>>()
  const edges = new Map<string, CyElement<CyEdgeData>>()
  for (const set of sets) {
    for (const n of set.nodes) nodes.set(n.data.id, n)
    for (const e of set.edges) edges.set(e.data.id, e)
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()] }
}
