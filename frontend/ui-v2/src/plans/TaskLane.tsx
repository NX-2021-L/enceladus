/**
 * ENC-TSK-S98-0B (ENC-PLN-108 W3.2): one task lane. Marks, in this order as the canvas draws them: wait line, work bar,
 * creation ring, close dot (Main.dc.html, States.dc.html). The bar colour is the task's status role and nothing else.
 */
import { RecordLink } from '../components/RecordLink'
import { StatusPill } from '../components/StatusPill'
import { pct } from './TimeAxis'
import type { TaskView } from './planView'

export function TaskLane({ task }: { task: TaskView }) {
  return (
    <div className="pl-row pl-task" title={task.tip}>
      <div className="pl-lab">
        <RecordLink id={task.id} recordType="task" className="enc-id" />
        <span className="pl-ttl">{task.title}</span>
        {task.showStatusPill && task.status ? <StatusPill status={task.status} kind="task" /> : null}
      </div>
      <div className="pl-track">
        {task.wait ? <span className="pl-wait" data-open={task.wait.open ? 'true' : undefined} style={{ left: pct(task.wait.leftPct), width: pct(task.wait.widthPct) }} /> : null}
        {task.work ? (
          <span className="pl-work" data-role={task.work.role} data-open={task.work.open ? 'true' : undefined} style={{ left: pct(task.work.leftPct), width: pct(task.work.widthPct) }} />
        ) : null}
        {task.createdPct !== null ? <span className="pl-c" style={{ left: pct(task.createdPct) }} /> : null}
        {task.closedPct !== null ? <span className="pl-z" style={{ left: pct(task.closedPct) }} /> : null}
      </div>
      <div className="pl-dur">
        <span>{task.waitText}</span>
        <span>{task.workText}</span>
      </div>
    </div>
  )
}
