/**
 * TypedRelationshipSection — displays typed relationship edges grouped by type.
 * Replaces flat RelatedItems display when typed edges are available.
 * (ENC-ISS-137 / ENC-FTR-049 / ENC-TSK-A57)
 */

import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { StatusChip } from './StatusChip'
import type { TypedRelationshipEdge, Task, Issue, Feature, Lesson } from '../../types/feeds'

// Human-readable labels for relationship types
const RELATIONSHIP_LABELS: Record<string, string> = {
  'blocks': 'Blocks',
  'blocked-by': 'Blocked By',
  'duplicates': 'Duplicates',
  'duplicated-by': 'Duplicated By',
  'relates-to': 'Relates To',
  'parent-of': 'Parent Of',
  'child-of': 'Child Of',
  'depends-on': 'Depends On',
  'depended-on-by': 'Depended On By',
  'clones': 'Clones',
  'cloned-by': 'Cloned By',
  'affects': 'Affects',
  'affected-by': 'Affected By',
  'tests': 'Tests',
  'tested-by': 'Tested By',
  'consumes-from': 'Consumes From',
  'produces-for': 'Produces For',
}

// Color coding per relationship category
const RELATIONSHIP_COLORS: Record<string, string> = {
  'blocks': 'text-red-400',
  'blocked-by': 'text-red-400',
  'depends-on': 'text-amber-400',
  'depended-on-by': 'text-amber-400',
  'duplicates': 'text-slate-400',
  'duplicated-by': 'text-slate-400',
  'relates-to': 'text-blue-400',
  'parent-of': 'text-emerald-400',
  'child-of': 'text-emerald-400',
  'affects': 'text-orange-400',
  'affected-by': 'text-orange-400',
  'tests': 'text-purple-400',
  'tested-by': 'text-purple-400',
  'clones': 'text-slate-400',
  'cloned-by': 'text-slate-400',
  'consumes-from': 'text-cyan-400',
  'produces-for': 'text-cyan-400',
}

interface RecordInfo {
  title: string
  status: string
  type: 'task' | 'issue' | 'feature' | 'lesson'
}

function getRecordPath(id: string, type: string): string {
  switch (type) {
    case 'task': return `/tasks/${id}`
    case 'issue': return `/issues/${id}`
    case 'feature': return `/features/${id}`
    case 'lesson': return `/lessons/${id}`
    default: return `/tasks/${id}`
  }
}

function detectRecordType(id: string): 'task' | 'issue' | 'feature' | 'lesson' {
  if (id.includes('-TSK-')) return 'task'
  if (id.includes('-ISS-')) return 'issue'
  if (id.includes('-FTR-')) return 'feature'
  if (id.includes('-LSN-')) return 'lesson'
  return 'task'
}

interface TypedRelationshipSectionProps {
  edges: TypedRelationshipEdge[]
  allTasks: Task[]
  allIssues: Issue[]
  allFeatures: Feature[]
  allLessons?: Lesson[]
}

export function TypedRelationshipSection({
  edges,
  allTasks,
  allIssues,
  allFeatures,
  allLessons = [],
}: TypedRelationshipSectionProps) {
  // Build record lookup map
  const recordMap = useMemo(() => {
    const map: Record<string, RecordInfo> = {}
    for (const t of allTasks) map[t.task_id] = { title: t.title, status: t.status, type: 'task' }
    for (const i of allIssues) map[i.issue_id] = { title: i.title, status: i.status, type: 'issue' }
    for (const f of allFeatures) map[f.feature_id] = { title: f.title, status: f.status, type: 'feature' }
    for (const l of allLessons) map[l.lesson_id] = { title: l.title, status: l.status, type: 'lesson' }
    return map
  }, [allTasks, allIssues, allFeatures, allLessons])

  // Group edges by relationship type
  const grouped = useMemo(() => {
    const groups: Record<string, TypedRelationshipEdge[]> = {}
    for (const edge of edges) {
      const key = edge.relationship_type
      if (!groups[key]) groups[key] = []
      groups[key].push(edge)
    }
    // Sort groups: blocking first, then dependencies, then rest
    const ORDER = ['blocks', 'blocked-by', 'depends-on', 'depended-on-by']
    return Object.entries(groups).sort(([a], [b]) => {
      const ai = ORDER.indexOf(a)
      const bi = ORDER.indexOf(b)
      if (ai !== -1 && bi !== -1) return ai - bi
      if (ai !== -1) return -1
      if (bi !== -1) return 1
      return a.localeCompare(b)
    })
  }, [edges])

  if (!edges.length) return null

  return (
    <div className="bg-slate-800 rounded-lg p-4">
      <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
        Typed Relationships ({edges.length})
      </h3>
      <div className="space-y-3">
        {grouped.map(([relType, groupEdges]) => (
          <div key={relType}>
            <div className="flex items-center gap-2 mb-1.5">
              <span className={`text-xs font-medium ${RELATIONSHIP_COLORS[relType] ?? 'text-slate-400'}`}>
                {RELATIONSHIP_LABELS[relType] ?? relType} ({groupEdges.length})
              </span>
            </div>
            <div className="space-y-1.5">
              {groupEdges.map((edge) => {
                const info = recordMap[edge.target_id]
                const recordType = info?.type ?? detectRecordType(edge.target_id)
                return (
                  <Link
                    key={`${relType}-${edge.target_id}`}
                    to={getRecordPath(edge.target_id, recordType)}
                    className="flex items-start gap-2 rounded-md bg-slate-700/50 p-2 hover:bg-slate-700 transition-colors"
                  >
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className="font-mono text-xs text-blue-400">{edge.target_id}</span>
                      {info && <StatusChip status={info.status} />}
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-slate-300 truncate">
                        {info?.title ?? edge.target_id}
                      </p>
                      {(edge.weight > 0 || edge.confidence > 0 || edge.reason) && (
                        <div className="flex items-center gap-2 mt-0.5">
                          {edge.weight > 0 && (
                            <span className="text-[10px] text-slate-500">
                              W:{edge.weight.toFixed(1)}
                            </span>
                          )}
                          {edge.confidence > 0 && (
                            <span className="text-[10px] text-slate-500">
                              C:{edge.confidence.toFixed(1)}
                            </span>
                          )}
                          {edge.reason && (
                            <span className="text-[10px] text-slate-500 truncate">
                              {edge.reason}
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  </Link>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
