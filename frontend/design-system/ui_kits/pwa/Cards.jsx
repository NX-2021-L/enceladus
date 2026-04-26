// Enceladus PWA — feed card rows. Matches prod TaskRow/LessonRow/ProjectCard.

function TaskRow({ task, onClick }) {
  return (
    <a onClick={(e) => { e.preventDefault(); onClick && onClick(task); }} href="#"
      className="block bg-slate-800 rounded-lg px-4 py-3 hover:bg-slate-700/80 active:bg-slate-700 transition-colors">
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-xs font-mono text-slate-500 shrink-0">{task.task_id}</span>
            <span className="text-xs text-slate-600">{task.project_id}</span>
          </div>
          <h4 className="text-sm font-medium text-slate-200 truncate">{task.title}</h4>
        </div>
        <span className="text-xs text-slate-500 shrink-0">{timeAgo(task.updated_at)}</span>
      </div>
      <div className="flex items-center gap-2 mt-1.5 flex-wrap">
        <StatusChip status={task.status} />
        <PriorityBadge priority={task.priority} />
        {task.active_agent_session && <ActiveSessionBadge isActive />}
        <CheckoutStateBadge
          activeSession={task.active_agent_session}
          checkoutState={task.checkout_state}
          checkedOutBy={task.checked_out_by}
          checkedOutAt={task.checked_out_at}
          checkedInBy={task.checked_in_by}
          checkedInAt={task.checked_in_at}
        />
        {task.checklist_total > 0 && (
          <span className="text-xs text-slate-500 font-mono">
            {task.checklist_done}/{task.checklist_total}
          </span>
        )}
        {task.parent && (
          <span className="text-xs text-blue-400 truncate" title={`Parent: ${task.parent}`}>
            Parent: {task.parent}
          </span>
        )}
      </div>
    </a>
  );
}

function IssueRow({ issue, onClick }) {
  return (
    <a onClick={(e) => { e.preventDefault(); onClick && onClick(issue); }} href="#"
      className="block bg-slate-800 rounded-lg px-4 py-3 hover:bg-slate-700/80 active:bg-slate-700 transition-colors">
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-xs font-mono text-slate-500">{issue.issue_id}</span>
            <span className="text-xs text-slate-600">{issue.project_id}</span>
          </div>
          <h4 className="text-sm font-medium text-slate-200 truncate">{issue.title}</h4>
        </div>
        <span className="text-xs text-slate-500 shrink-0">{timeAgo(issue.updated_at)}</span>
      </div>
      <div className="flex items-center gap-2 mt-1.5 flex-wrap">
        <StatusChip status={issue.status} />
        <PriorityBadge priority={issue.priority} />
        {issue.parent && <span className="text-xs text-blue-400">Parent: {issue.parent}</span>}
      </div>
    </a>
  );
}

function FeatureRow({ feature, onClick }) {
  return (
    <a onClick={(e) => { e.preventDefault(); onClick && onClick(feature); }} href="#"
      className="block bg-slate-800 rounded-lg px-4 py-3 hover:bg-slate-700/80 active:bg-slate-700 transition-colors">
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-xs font-mono text-slate-500">{feature.feature_id}</span>
            <span className="text-xs text-slate-600">{feature.project_id}</span>
          </div>
          <h4 className="text-sm font-medium text-slate-200 truncate">{feature.title}</h4>
        </div>
        <span className="text-xs text-slate-500 shrink-0">{timeAgo(feature.updated_at)}</span>
      </div>
      <div className="flex items-center gap-2 mt-1.5"><StatusChip status={feature.status} /></div>
    </a>
  );
}

function LessonRow({ lesson, onClick }) {
  const composite = typeof lesson.pillar_composite === 'number' ? lesson.pillar_composite.toFixed(2) : null;
  return (
    <a onClick={(e) => { e.preventDefault(); onClick && onClick(lesson); }} href="#"
      className="block bg-slate-800 rounded-lg px-4 py-3 hover:bg-slate-700/80 active:bg-slate-700 transition-colors">
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-xs font-mono text-slate-500">{lesson.lesson_id}</span>
            <span className="text-xs text-slate-600">{lesson.project_id}</span>
          </div>
          <h4 className="text-sm font-medium text-slate-200 truncate">{lesson.title}</h4>
        </div>
        <span className="text-xs text-slate-500 shrink-0">{timeAgo(lesson.updated_at)}</span>
      </div>
      <div className="flex items-center gap-2 mt-1.5 flex-wrap">
        <StatusChip status={lesson.status} />
        <CategoryTag category={lesson.category} />
        {lesson.provenance && <span className="text-xs text-slate-500">{lesson.provenance}</span>}
        {composite && <span className="text-xs font-mono text-purple-300" title="Pillar Composite">{composite}</span>}
        {typeof lesson.confidence === 'number' && (
          <span className="text-xs text-slate-500" title="Confidence">conf: {(lesson.confidence * 100).toFixed(0)}%</span>
        )}
      </div>
    </a>
  );
}

function ProjectCard({ project, onClick }) {
  return (
    <a onClick={(e) => { e.preventDefault(); onClick && onClick(project); }} href="#"
      className="block bg-slate-800 rounded-lg p-4 hover:bg-slate-700/80 active:bg-slate-700 transition-colors">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-500">{project.prefix}</span>
          <h3 className="font-medium text-slate-100">{project.name}</h3>
        </div>
        <span className="text-xs text-slate-500">{timeAgo(project.updated_at)}</span>
      </div>
      {project.summary && <p className="text-sm text-slate-400 mb-3 line-clamp-2">{project.summary}</p>}
      <div className="flex gap-4 text-xs text-slate-500">
        <span><span className="text-blue-400 font-medium">{project.open_tasks}</span> tasks</span>
        <span><span className="text-amber-400 font-medium">{project.open_issues}</span> issues</span>
        <span><span className="text-emerald-400 font-medium">{project.completed_features}</span> live features</span>
      </div>
    </a>
  );
}

function DocumentRow({ doc, onClick }) {
  return (
    <a onClick={(e) => { e.preventDefault(); onClick && onClick(doc); }} href="#"
      className="block bg-slate-800 rounded-lg px-4 py-3 hover:bg-slate-700/80 active:bg-slate-700 transition-colors">
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-xs font-mono text-slate-500">{doc.doc_id}</span>
            <span className="text-xs text-slate-600">{doc.project_id}</span>
          </div>
          <h4 className="text-sm font-medium text-slate-200 truncate">{doc.title}</h4>
        </div>
        <span className="text-xs text-slate-500 shrink-0">{doc.updated_at}</span>
      </div>
      <div className="flex items-center gap-2 mt-1.5">
        <CategoryTag category={doc.kind} />
      </div>
    </a>
  );
}

function FeedSectionTitle({ children, count }) {
  return (
    <div className="flex items-baseline justify-between px-1 mt-6 mb-2">
      <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{children}</h3>
      {typeof count === 'number' && <span className="text-xs text-slate-500 font-mono">{count}</span>}
    </div>
  );
}

Object.assign(window, { TaskRow, IssueRow, FeatureRow, LessonRow, ProjectCard, DocumentRow, FeedSectionTitle });
