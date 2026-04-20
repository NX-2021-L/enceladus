// Enceladus PWA — composed screens.

function DashboardScreen({ onOpen }) {
  const d = window.encData;
  const stats = {
    records: 2789, projects: d.projects.length,
    openIssues: d.issues.filter(i => i.status !== 'closed').length,
    activeSessions: d.tasks.filter(t => t.active_agent_session).length,
  };
  return (
    <div className="px-4 pt-4 space-y-4">
      <div className="grid grid-cols-2 gap-2">
        <div className="bg-slate-800 rounded-lg p-3">
          <div className="text-2xl font-semibold text-slate-100 tabular-nums">{stats.records.toLocaleString()}</div>
          <div className="text-xs text-slate-500 uppercase tracking-wider mt-0.5">Records</div>
        </div>
        <div className="bg-slate-800 rounded-lg p-3">
          <div className="text-2xl font-semibold text-slate-100 tabular-nums">{stats.projects}</div>
          <div className="text-xs text-slate-500 uppercase tracking-wider mt-0.5">Projects</div>
        </div>
        <div className="bg-slate-800 rounded-lg p-3">
          <div className="text-2xl font-semibold text-red-300 tabular-nums">{stats.openIssues}</div>
          <div className="text-xs text-slate-500 uppercase tracking-wider mt-0.5">Open issues</div>
        </div>
        <div className="bg-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <div className="text-2xl font-semibold text-emerald-300 tabular-nums">{stats.activeSessions}</div>
          </div>
          <div className="text-xs text-slate-500 uppercase tracking-wider mt-0.5">Active sessions</div>
        </div>
      </div>

      <div className="bg-slate-800/60 rounded-lg p-4 border border-slate-700/40">
        <div className="flex items-baseline justify-between mb-3">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Constitutional Pillars</h3>
          <span className="text-xs font-mono text-purple-300">composite 0.823</span>
        </div>
        {[
          ['Efficiency', 0.82, 'bg-sky-400'],
          ['Human Protection', 0.91, 'bg-slate-200'],
          ['Intention', 0.76, 'bg-teal-400'],
          ['Alignment', 0.79, 'bg-purple-400'],
        ].map(([name, val, bar]) => (
          <div key={name} className="flex items-center gap-2.5 my-1.5">
            <span className="text-xs text-slate-300 w-32">{name}</span>
            <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
              <div className={`h-full ${bar}`} style={{ width: `${val*100}%` }} />
            </div>
            <span className="text-xs font-mono text-slate-400 w-8 text-right tabular-nums">{val.toFixed(2)}</span>
          </div>
        ))}
      </div>

      <div>
        <FeedSectionTitle count={d.tasks.length}>Active tasks</FeedSectionTitle>
        <div className="space-y-2">
          {d.tasks.slice(0, 3).map(t => <TaskRow key={t.task_id} task={t} onClick={onOpen} />)}
        </div>
      </div>

      <div>
        <FeedSectionTitle count={d.lessons.length}>Recent lessons</FeedSectionTitle>
        <div className="space-y-2">
          {d.lessons.slice(0, 2).map(l => <LessonRow key={l.lesson_id} lesson={l} onClick={onOpen} />)}
        </div>
      </div>
    </div>
  );
}

function ProjectsScreen({ onOpen }) {
  return (
    <div className="px-4 pt-4 space-y-2">
      {window.encData.projects.map(p => <ProjectCard key={p.project_id} project={p} onClick={onOpen} />)}
    </div>
  );
}

function FeedScreen({ onOpen }) {
  const d = window.encData;
  return (
    <div className="px-4 pt-4 pb-2">
      <FeedSectionTitle count={d.issues.length}>Issues</FeedSectionTitle>
      <div className="space-y-2">{d.issues.map(i => <IssueRow key={i.issue_id} issue={i} onClick={onOpen} />)}</div>
      <FeedSectionTitle count={d.tasks.length}>Tasks</FeedSectionTitle>
      <div className="space-y-2">{d.tasks.map(t => <TaskRow key={t.task_id} task={t} onClick={onOpen} />)}</div>
      <FeedSectionTitle count={d.features.length}>Features</FeedSectionTitle>
      <div className="space-y-2">{d.features.map(f => <FeatureRow key={f.feature_id} feature={f} onClick={onOpen} />)}</div>
      <FeedSectionTitle count={d.lessons.length}>Lessons</FeedSectionTitle>
      <div className="space-y-2">{d.lessons.map(l => <LessonRow key={l.lesson_id} lesson={l} onClick={onOpen} />)}</div>
    </div>
  );
}

function DocsScreen({ onOpen }) {
  return (
    <div className="px-4 pt-4 space-y-2">
      {window.encData.docs.map(d => <DocumentRow key={d.doc_id} doc={d} onClick={onOpen} />)}
    </div>
  );
}

function ChangelogScreen() {
  return (
    <div className="px-4 pt-4 space-y-2">
      {window.encData.changelog.map(c => (
        <div key={c.version} className="bg-slate-800 rounded-lg px-4 py-3">
          <div className="flex items-baseline justify-between mb-1">
            <div className="flex items-center gap-2">
              <span className="text-sm font-mono text-blue-300">{c.version}</span>
              <span className="text-xs text-slate-600">{c.project}</span>
            </div>
            <span className="text-xs text-slate-500 font-mono">{c.date}</span>
          </div>
          <p className="text-sm text-slate-300">{c.note}</p>
        </div>
      ))}
    </div>
  );
}

function DetailSheet({ record, onClose }) {
  if (!record) return null;
  const idKey = Object.keys(record).find(k => k.endsWith('_id')) || 'id';
  const id = record[idKey];
  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-end sm:items-center justify-center p-0 sm:p-4" onClick={onClose}>
      <div className="bg-slate-900 border-t sm:border border-slate-700 sm:rounded-xl w-full max-w-lg max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="sticky top-0 bg-slate-900/95 backdrop-blur border-b border-slate-700/60 px-4 py-3 flex items-center justify-between">
          <span className="text-xs font-mono text-blue-400">{id}</span>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.75}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="px-4 py-4">
          <h2 className="text-lg font-semibold text-slate-100 mb-3">{record.title || record.name}</h2>
          <div className="space-y-2 text-sm">
            {Object.entries(record).map(([k, v]) => (
              <div key={k} className="flex gap-3 items-baseline border-b border-slate-800 pb-1.5">
                <span className="text-xs uppercase tracking-wider text-slate-500 w-32 shrink-0">{k.replace(/_/g, ' ')}</span>
                <span className="text-slate-300 font-mono text-xs break-all">{v === null || v === undefined ? '—' : String(v)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { DashboardScreen, ProjectsScreen, FeedScreen, DocsScreen, ChangelogScreen, DetailSheet });
