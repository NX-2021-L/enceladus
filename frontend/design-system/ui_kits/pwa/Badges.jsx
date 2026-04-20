// Enceladus PWA — badges. Matches prod (Tailwind slate-*/blue/amber/purple).
const { Fragment } = React;

function timeAgo(iso) {
  if (!iso) return '';
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function StatusChip({ status }) {
  const map = {
    'open':         'bg-blue-500/20 text-blue-300',
    'in-progress':  'bg-sky-500/20 text-sky-300',
    'blocked':      'bg-red-500/20 text-red-300',
    'closed':       'bg-slate-700/50 text-slate-400',
    'draft':        'bg-purple-500/15 text-purple-300 italic',
  };
  const cls = map[status] || map['open'];
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {status}
    </span>
  );
}

function PriorityBadge({ priority }) {
  if (!priority) return null;
  const map = {
    'P0': 'bg-red-500/20 text-red-300 border border-red-500/40',
    'P1': 'bg-amber-500/20 text-amber-300 border border-amber-500/30',
    'P2': 'bg-slate-700/50 text-slate-400',
    'P3': 'bg-slate-700/30 text-slate-500',
  };
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono font-medium ${map[priority] || map['P2']}`}>
      {priority}
    </span>
  );
}

function CheckoutStateBadge({ activeSession, checkoutState, checkedOutBy, checkedInBy, checkedOutAt, checkedInAt }) {
  if (activeSession || checkoutState === 'checked_out') {
    const who = checkedOutBy ? ` by ${checkedOutBy}` : '';
    const when = checkedOutAt ? ` (${timeAgo(checkedOutAt)})` : '';
    return (
      <span title={`Checked out${who}${when}`}
        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-amber-500/20 text-amber-300">
        Checked Out
      </span>
    );
  }
  if (checkoutState === 'checked_in') {
    const who = checkedInBy ? ` by ${checkedInBy}` : '';
    const when = checkedInAt ? ` (${timeAgo(checkedInAt)})` : '';
    return (
      <span title={`Checked in${who}${when}`}
        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-sky-500/20 text-sky-300">
        Checked In
      </span>
    );
  }
  return null;
}

function ActiveSessionBadge({ isActive }) {
  if (!isActive) return null;
  return (
    <span title="Active agent session"
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium bg-emerald-500/15 text-emerald-300">
      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
      active
    </span>
  );
}

function CategoryTag({ category }) {
  if (!category) return null;
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-500/20 text-purple-400">
      {category}
    </span>
  );
}

Object.assign(window, {
  StatusChip, PriorityBadge, CheckoutStateBadge, ActiveSessionBadge, CategoryTag,
  timeAgo,
});
