// Enceladus v2 · CollectionPreferences — Cloudscape CollectionPreferences, deep re-brand.
const ev2CpCss = `
.ev2-cp{position:relative;font-family:var(--font-body,'Inter',sans-serif)}
.ev2-cp__gear{width:var(--v2-control-height,32px);height:var(--v2-control-height,32px);border:1px solid var(--v2-field-border,rgba(61,155,168,.3));background:var(--v2-field-bg,#0D1220);border-radius:var(--v2-control-radius,6px);color:var(--enc-dust,#6B8A94);cursor:pointer;display:inline-flex;align-items:center;justify-content:center;transition:all var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-cp__gear:hover{color:var(--enc-teal-light,#7AC8D4);border-color:rgba(61,155,168,.5)}
.ev2-cp__pop{position:absolute;top:calc(100% + 4px);right:0;z-index:20;width:280px;background:var(--enc-surface,#111827);border:1px solid var(--v2-panel-border,rgba(61,155,168,.25));border-radius:var(--v2-panel-radius,8px);box-shadow:var(--v2-dropdown-shadow,0 8px 32px rgba(0,0,0,.6));padding:14px 16px}
.ev2-cp__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:14px;color:var(--enc-seafoam,#C8DDD9);margin:0 0 10px}
.ev2-cp__group{margin-bottom:14px}
.ev2-cp__grouplbl{font-size:11px;font-weight:500;text-transform:uppercase;letter-spacing:.06em;color:var(--enc-dust,#6B8A94);margin-bottom:6px}
.ev2-cp__foot{display:flex;justify-content:flex-end;gap:8px;margin-top:6px;padding-top:12px;border-top:1px solid var(--v2-divider,rgba(61,155,168,.12))}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-cp-css')){const s=document.createElement('style');s.id='ev2-cp-css';s.textContent=ev2CpCss;document.head.appendChild(s);}})();

export function CollectionPreferences({ title = 'Preferences', pageSizeOptions = [], pageSize, visibleColumns = [], columnOptions = [], onConfirm }) {
  const NS = (typeof window !== 'undefined' && window.EnceladusDesignSystem_7eb1fe) || {};
  const [open, setOpen] = React.useState(false);
  const [size, setSize] = React.useState(pageSize);
  const [cols, setCols] = React.useState(visibleColumns);
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!open) return;
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);
  const toggleCol = (id) => setCols((c) => c.includes(id) ? c.filter((x) => x !== id) : [...c, id]);
  return (
    <div className="ev2-cp" ref={ref}>
      <button className="ev2-cp__gear" aria-label="Preferences" onClick={() => setOpen((o) => !o)}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
      </button>
      {open && (
        <div className="ev2-cp__pop" role="dialog">
          <h3 className="ev2-cp__title">{title}</h3>
          {pageSizeOptions.length > 0 && NS.RadioGroup && (
            <div className="ev2-cp__group">
              <div className="ev2-cp__grouplbl">Page size</div>
              <NS.RadioGroup value={String(size)} onChange={(ev) => setSize(Number(ev.detail.value))}
                items={pageSizeOptions.map((o) => ({ value: String(o.value), label: o.label }))} />
            </div>
          )}
          {columnOptions.length > 0 && NS.Checkbox && (
            <div className="ev2-cp__group">
              <div className="ev2-cp__grouplbl">Visible columns</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {columnOptions.map((c) => (
                  <NS.Checkbox key={c.id} checked={cols.includes(c.id)} onChange={() => toggleCol(c.id)}>{c.label}</NS.Checkbox>
                ))}
              </div>
            </div>
          )}
          <div className="ev2-cp__foot">
            {NS.Button && <NS.Button onClick={() => setOpen(false)}>Cancel</NS.Button>}
            {NS.Button && <NS.Button variant="primary" onClick={() => { onConfirm && onConfirm({ detail: { pageSize: size, visibleColumns: cols } }); setOpen(false); }}>Confirm</NS.Button>}
          </div>
        </div>
      )}
    </div>
  );
}
