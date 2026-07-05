import { Link } from '@tanstack/react-router'
import type { TypedRelationshipEdge } from '../types/records'
import { recordHrefForType } from '../routes/recordLink'

const RELATIONSHIP_LABELS: Record<string, string> = {
  'blocks': 'Blocks',
  'blocked-by': 'Blocked By',
  'depends-on': 'Depends On',
  'relates-to': 'Relates To',
  'parent-of': 'Parent Of',
  'child-of': 'Child Of',
  'plan-contains': 'Plan Contains',
  'informed-by': 'Informed By',
  'learned-from': 'Learned From',
  'related-to': 'Related To',
}

function detectRecordType(id: string): 'task' | 'issue' | 'feature' | 'lesson' | 'plan' {
  if (id.includes('-PLN-')) return 'plan'
  if (id.includes('-ISS-')) return 'issue'
  if (id.includes('-FTR-')) return 'feature'
  if (id.includes('-LSN-')) return 'lesson'
  return 'task'
}

export function TypedRelationshipSection({
  projectId,
  edges,
}: {
  projectId: string
  edges: TypedRelationshipEdge[]
}) {
  if (!edges.length) return null

  const grouped = edges.reduce<Record<string, TypedRelationshipEdge[]>>((acc, edge) => {
    const key = edge.relationship_type
    acc[key] = acc[key] ?? []
    acc[key].push(edge)
    return acc
  }, {})

  return (
    <section style={{ marginTop: 'var(--space-5)' }}>
      <h4
        style={{
          margin: '0 0 var(--space-3)',
          fontFamily: 'var(--font-heading)',
          fontSize: 'var(--text-sm)',
          color: 'var(--fg-display)',
        }}
      >
        Typed relationships
      </h4>
      {Object.entries(grouped).map(([relType, relEdges]) => (
        <div key={relType} style={{ marginBottom: 'var(--space-3)' }}>
          <div
            style={{
              fontSize: 'var(--text-xs)',
              textTransform: 'uppercase',
              letterSpacing: 'var(--tracking-label)',
              color: 'var(--accent)',
              marginBottom: 'var(--space-2)',
            }}
          >
            {RELATIONSHIP_LABELS[relType] ?? relType}
          </div>
          <ul style={{ margin: 0, paddingLeft: 'var(--space-5)' }}>
            {relEdges.map((edge) => {
              const targetType = detectRecordType(edge.target_id)
              return (
                <li key={`${relType}-${edge.target_id}`} style={{ marginBottom: 'var(--space-1)' }}>
                  <Link
                    to={recordHrefForType(projectId, targetType, edge.target_id)}
                    style={{ color: 'var(--fg-body)', textDecoration: 'none' }}
                  >
                    {edge.target_id}
                  </Link>
                  {edge.reason ? (
                    <span style={{ color: 'var(--fg-muted)', fontSize: 'var(--text-xs)' }}>
                      {' '}
                      — {edge.reason}
                    </span>
                  ) : null}
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </section>
  )
}
