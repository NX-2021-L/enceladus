// Enceladus v2 · Autosuggest — Cloudscape Autosuggest, deep re-brand.
const ev2AutoCss = `
.ev2-auto{position:relative;font-family:var(--font-body,'Inter',sans-serif);width:100%}
.ev2-auto__menu{position:absolute;top:calc(100% + 4px);left:0;right:0;z-index:20;background:var(--enc-surface,#111827);border:1px solid var(--v2-panel-border,rgba(61,155,168,.25));border-radius:var(--v2-panel-radius,8px);box-shadow:var(--v2-dropdown-shadow,0 8px 32px rgba(0,0,0,.6));padding:4px;max-height:220px;overflow-y:auto}
.ev2-auto__opt{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:7px 10px;border-radius:4px;cursor:pointer;font-size:14px;color:var(--enc-starlight,#EEF2F7);transition:background var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-auto__opt:hover,.ev2-auto__opt--active{background:rgba(61,155,168,.1)}
.ev2-auto__opt mark{background:none;color:var(--enc-teal-light,#7AC8D4);font-weight:600}
.ev2-auto__tag{font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-dust,#6B8A94)}
.ev2-auto__empty{padding:9px 10px;font-size:13px;color:var(--enc-dust,#6B8A94)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-auto-css')){const s=document.createElement('style');s.id='ev2-auto-css';s.textContent=ev2AutoCss;document.head.appendChild(s);}})();

function ev2Highlight(text, q) {
  if (!q) return text;
  const i = String(text).toLowerCase().indexOf(q.toLowerCase());
  if (i < 0) return text;
  const t = String(text);
  return [t.slice(0, i), React.createElement('mark', { key: 'm' }, t.slice(i, i + q.length)), t.slice(i + q.length)];
}

export function Autosuggest({ value = '', options = [], placeholder, onChange, emptyText = 'No matches', ariaLabel }) {
  const NS = (typeof window !== 'undefined' && window.EnceladusDesignSystem_7eb1fe) || {};
  const InputCmp = NS.Input;
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!open) return;
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);
  const filtered = options.filter((o) => String(o.value).toLowerCase().includes(value.toLowerCase()));
  const handle = (v) => { onChange && onChange({ detail: { value: v } }); setOpen(true); };
  return (
    <div className="ev2-auto" ref={ref}>
      {InputCmp
        ? <InputCmp value={value} placeholder={placeholder} ariaLabel={ariaLabel} onChange={(ev) => handle(ev.detail.value)} />
        : <input value={value} placeholder={placeholder} aria-label={ariaLabel} onChange={(ev) => handle(ev.target.value)}
            style={{ width: '100%', height: 32, padding: '0 12px', background: '#0D1220', border: '1px solid rgba(61,155,168,.25)', borderRadius: 6, color: '#EEF2F7', fontSize: 14, boxSizing: 'border-box' }} />}
      {open && (
        <div className="ev2-auto__menu" role="listbox">
          {filtered.length === 0 && <div className="ev2-auto__empty">{emptyText}</div>}
          {filtered.map((opt) => (
            <div key={opt.value} role="option" className="ev2-auto__opt"
              onMouseDown={() => { onChange && onChange({ detail: { value: opt.value } }); setOpen(false); }}>
              <span>{ev2Highlight(opt.value, value)}{opt.description && <span className="ev2-auto__tag" style={{ marginLeft: 8 }}>{opt.description}</span>}</span>
              {opt.tag && <span className="ev2-auto__tag">{opt.tag}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
