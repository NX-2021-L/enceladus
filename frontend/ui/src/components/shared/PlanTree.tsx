/**
 * PlanTree — hierarchical visualization of parent-child task relationships.
 * Shows up to 3 levels with connector lines, expand/collapse, and status badges.
 * Detects [Plan] prefix for plan parent styling.
 * (ENC-ISS-139 / ENC-TSK-A57)
 */

import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { StatusChip } from './StatusChip'
import type { Task } from '../../types/feeds'

interface TreeNode {
  task: Task
  children: TreeNode[]
  depth: number
}

interface PlanTreeProps {
  /** The root task (parent with subtask_ids) */
  rootTask: Task
  /** All tasks from the feed — used to resolve child IDs */
  allTasks: Task[]
  /** Max depth to render (default 3) */
  maxDepth?: number
}

function buildTree(root: Task, taskMap: Map<string, Task>, maxDepth: number): TreeNode {
  function recurse(task: Task, depth: number): TreeNode {
    const children: TreeNode[] = []
    if (depth < maxDepth && task.subtask_ids?.length) {
      for (const childId of task.subtask_ids) {
        const child = taskMap.get(childId)
        if (child) {
          children.push(recurse(child, depth + 1))
        }
      }
    }
    // Sort children by ID for consistent ordering
    children.sort((a, b) => a.task.task_id.localeCompare(b.task.task_id))
    return { task, children, depth }
  }
  return recurse(root, 0)
}

const STATUS_COLORS: Record<string, string> = {
  'open': 'border-slate-500',
  'in-progress': 'border-blue-500',
  'coding-complete': 'border-yellow-500',
  'committed': 'border-orange-500',
  'pr': 'border-purple-500',
  'merged-main': 'border-indigo-500',
  'deploy-init': 'border-cyan-500',
  'deploy-success': 'border-emerald-500',
  'coding-updates': 'border-amber-500',
  'closed': 'border-emerald-600',
}

function TreeNodeRow({
  node,
  isLast,
  parentConnectors,
}: {
  node: TreeNode
  isLast: boolean
  parentConnectors: boolean[]
}) {
  const [expanded, setExpanded] = useState(node.depth < 2) // Auto-expand first 2 levels
  const hasChildren = node.children.length > 0
  const isPlan = node.task.title.startsWith('[Plan]')
  const borderColor = STATUS_COLORS[node.task.status] ?? 'border-slate-500'

  return (
    <div>
      <div className="flex items-start">
        {/* Connector lines */}
        <div className="flex flex-shrink-0">
          {parentConnectors.map((showLine, i) => (
            <div key={i} className="w-5 flex-shrink-0">
              {showLine && (
                <div className="w-px h-full bg-slate-600 ml-2" />
              )}
            </div>
          ))}
          {node.depth > 0 && (
            <div className="w-5 flex-shrink-0 flex items-start">
              <div className={`w-px ${isLast ? 'h-3' : 'h-full'} bg-slate-600 ml-2`} />
              <div className="w-3 h-px bg-slate-600 mt-3" />
            </div>
          )}
        </div>

        {/* Node content */}
        <div
          className={`flex-1 min-w-0 flex items-center gap-2 rounded-md p-1.5 hover:bg-slate-700/50 transition-colors ${
            isPlan ? 'bg-slate-700/30' : ''
          }`}
        >
          {/* Expand/collapse toggle */}
          {hasChildren ? (
            <button
              onClick={() => setExpanded(!expanded)}
              className="flex-shrink-0 w-4 h-4 flex items-center justify-center text-slate-500 hover:text-slate-300"
            >
              <svg
                className={`w-3 h-3 transition-transform ${expanded ? 'rotate-90' : ''}`}
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <path d="M6 4l8 6-8 6V4z" />
              </svg>
            </button>
          ) : (
            <div className="w-4 flex-shrink-0" />
          )}

          {/* Status dot */}
          <div className={`w-2 h-2 rounded-full border ${borderColor} flex-shrink-0`} />

          {/* ID + title */}
          <Link
            to={`/tasks/${node.task.task_id}`}
            className="flex items-center gap-2 min-w-0 flex-1"
          >
            <span className="font-mono text-[10px] text-blue-400 flex-shrink-0">
              {node.task.task_id}
            </span>
            <StatusChip status={node.task.status} />
            <span className={`text-xs truncate ${isPlan ? 'text-slate-200 font-medium' : 'text-slate-400'}`}>
              {node.task.title}
            </span>
          </Link>
        </div>
      </div>

      {/* Children */}
      {expanded && hasChildren && (
        <div>
          {node.children.map((child, idx) => (
            <TreeNodeRow
              key={child.task.task_id}
              node={child}
              isLast={idx === node.children.length - 1}
              parentConnectors={[
                ...parentConnectors,
                ...(node.depth > 0 ? [!isLast] : []),
              ]}
            />
          ))}
        </div>
      )}
    </div>
  )
}

export function PlanTree({ rootTask, allTasks, maxDepth = 3 }: PlanTreeProps) {
  const tree = useMemo(() => {
    const taskMap = new Map<string, Task>()
    for (const t of allTasks) taskMap.set(t.task_id, t)
    return buildTree(rootTask, taskMap, maxDepth)
  }, [rootTask, allTasks, maxDepth])

  // Don't render if no children
  if (!tree.children.length) return null

  return (
    <div className="bg-slate-800 rounded-lg p-4">
      <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
        Plan Tree ({tree.children.length} subtask{tree.children.length !== 1 ? 's' : ''})
      </h3>
      <div className="overflow-x-auto">
        <TreeNodeRow node={tree} isLast parentConnectors={[]} />
      </div>
    </div>
  )
}
