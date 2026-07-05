import { useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import cytoscape, { type Core } from 'cytoscape'
import { fetchGraphNeighbors, graphKeys } from '../api/graph'
import { recordHref } from '../routes/recordLink'
import './plan-graph.css'

const PLAN_EDGE_TYPES = ['PLAN_CONTAINS', 'INFORMED_BY', 'LEARNED_FROM', 'RELATED_TO', 'PLAN_ATTACHED_DOC']

export function PlanGraphExplorer({
  projectId,
  planId,
  objectiveIds = [],
}: {
  projectId: string
  planId: string
  objectiveIds?: string[]
}) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const cyRef = useRef<Core | null>(null)

  const { data, isPending, isError, error } = useQuery({
    queryKey: graphKeys.neighbors(projectId, planId, PLAN_EDGE_TYPES.join(',')),
    queryFn: () =>
      fetchGraphNeighbors({
        projectId,
        recordId: planId,
        edgeTypes: PLAN_EDGE_TYPES,
        depth: 2,
      }),
    staleTime: 30_000,
  })

  useEffect(() => {
    const el = containerRef.current
    if (!el || !data?.nodes?.length) return

    const nodeIds = new Set<string>([planId, ...objectiveIds])
    for (const n of data.nodes) {
      const id = String(n.record_id ?? '')
      if (id) nodeIds.add(id)
    }

    const elements: cytoscape.ElementDefinition[] = []
    for (const id of nodeIds) {
      const hit = data.nodes.find((n) => n.record_id === id)
      const label = String(hit?.title ?? id)
      const isPlan = id === planId
      const isObjective = objectiveIds.includes(id)
      elements.push({
        data: {
          id,
          label: label.length > 28 ? `${label.slice(0, 26)}…` : label,
        },
        classes: isPlan ? 'plan-root' : isObjective ? 'plan-objective' : 'plan-neighbor',
      })
    }

    for (const edge of data.edges ?? []) {
      const start = edge.start
      const end = edge.end
      if (!nodeIds.has(start) || !nodeIds.has(end)) continue
      elements.push({
        data: {
          id: `${start}-${edge.type}-${end}`,
          source: start,
          target: end,
          label: edge.type,
        },
      })
    }

    cyRef.current?.destroy()
    const cy = cytoscape({
      container: el,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-size': 10,
            color: '#e2e8f0',
            'background-color': '#334155',
            width: 36,
            height: 36,
          },
        },
        {
          selector: '.plan-root',
          style: {
            'background-color': '#0ea5a4',
            width: 52,
            height: 52,
            'box-shadow': '0 0 16px rgba(14, 165, 164, 0.55)',
          },
        },
        {
          selector: '.plan-objective',
          style: {
            'background-color': '#0369a1',
            'box-shadow': '0 0 10px rgba(3, 105, 161, 0.45)',
          },
        },
        {
          selector: 'edge',
          style: {
            width: 2,
            'line-color': '#64748b',
            'target-arrow-color': '#64748b',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': 8,
            color: '#94a3b8',
          },
        },
      ],
      layout: { name: 'concentric', concentric: (node) => (node.id() === planId ? 2 : 1), levelWidth: () => 2 },
    })

    cy.on('tap', 'node', (evt) => {
      const id = evt.target.id()
      if (id === planId) return
      const type = id.includes('-PLN-') ? 'plan' : 'task'
      window.location.assign(recordHref(projectId, type, id))
    })

    cyRef.current = cy
    return () => {
      cy.destroy()
      cyRef.current = null
    }
  }, [data, planId, projectId, objectiveIds])

  return (
    <section className="plan-graph" aria-label="Plan graph explorer">
      <div className="plan-graph__header">
        <h4 className="plan-graph__title">Plan graph</h4>
        <p className="plan-graph__subtitle">
          Cytoscape view of PLAN_CONTAINS and typed plan edges (ENC-PLN-006 objectives).
        </p>
      </div>
      {isPending ? <p className="plan-graph__status">Loading graph…</p> : null}
      {isError ? (
        <p className="plan-graph__status plan-graph__status--error">
          {error instanceof Error ? error.message : 'Graph unavailable'}
        </p>
      ) : null}
      <div ref={containerRef} className="plan-graph__canvas" />
      {data?.summary ? <p className="plan-graph__summary">{data.summary}</p> : null}
    </section>
  )
}
