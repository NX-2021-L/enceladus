// Enceladus v2 · DatePicker — Cloudscape DatePicker, deep re-brand.
const ev2DateCss = `
.ev2-date{position:relative;font-family:var(--font-body,'Inter',sans-serif);width:100%;max-width:260px}
.ev2-date__trigger{display:flex;align-items:center;gap:8px;width:100%;height:var(--v2-control-height,32px);padding:0 10px 0 12px;background:var(--v2-field-bg,#0D1220);border:1px solid var(--v2-field-border,rgba(61,155,168,.25));border-radius:var(--v2-control-radius,6px);color:var(--enc-starlight,#EEF2F7);font-family:var(--font-mono,monospace);font-size:13px;cursor:pointer;box-sizing:border-box;transition:border-color var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),box-shadow var(--dur-base,200ms) var(--ease-orbit)}
.ev2-date__trigger:hover{border-color:var(--v2-field-border-hover,rgba(61,155,168,.45))}
.ev2-date--open .ev2-date__trigger{border-color:var(--v2-field-border-focus,#3D9BA8);box-shadow:var(--v2-focus-ring)}
.ev2-date__ph{color:var(--v2-field-placeholder,#4A5E68)}
.ev2-date__ico{margin-left:auto;color:var(--enc-dust,#6B8A94);display:flex}
.ev2-date__pop{position:absolute;top:calc(100% + 4px);left:0;z-index:20;background:var(--enc-surface,#111827);border:1px solid var(--v2-panel-border,rgba(61,155,168,.25));border-radius:var(--v2-panel-radius,8px);box-shadow:var(--v2-dropdown-shadow,0 8px 32px rgba(0,0,0,.6));padding:12px;width:252px}
.ev2-date__nav{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.ev2-date__nav button{appearance:none;border:none;background:none;color:var(--enc-dust,#6B8A94);cursor:pointer;font-size:16px;padding:2px 8px;border-radius:4px}
.ev2-date__nav button:hover{color:var(--enc-teal-light,#7AC8D4);background:rgba(61,155,168,.1)}
.ev2-date__month{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;color:var(--enc-seafoam,#C8DDD9)}
.ev2-date__grid{display:grid;grid-template-columns:repeat(7,1fr);gap:2px}
.ev2-date__dow{font-family:var(--font-mono,monospace);font-size:10px;color:var(--enc-dust,#6B8A94);text-align:center;padding:4px 0}
.ev2-date__day{appearance:none;border:none;background:none;color:var(--enc-starlight,#EEF2F7);font-family:var(--font-mono,monospace);font-size:12px;aspect-ratio:1;border-radius:4px;cursor:pointer;transition:background var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-date__day:hover{background:rgba(61,155,168,.15)}
.ev2-date__day--sel{background:var(--enc-teal,#3D9BA8);color:var(--enc-void,#0A0A0F)}
.ev2-date__day--empty{visibility:hidden}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-date-css')){const s=document.createElement('style');s.id='ev2-date-css';s.textContent=ev2DateCss;document.head.appendChild(s);}})();

const EV2_DOW = ['Su','Mo','Tu','We','Th','Fr','Sa'];
const EV2_MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];

export function DatePicker({ value = '', placeholder = 'YYYY/MM/DD', onChange }) {
  const [open, setOpen] = React.useState(false);
  const init = value ? new Date(value.replace(/\//g, '-')) : new Date();
  const [view, setView] = React.useState({ y: init.getFullYear(), m: init.getMonth() });
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!open) return;
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);
  const first = new Date(view.y, view.m, 1).getDay();
  const days = new Date(view.y, view.m + 1, 0).getDate();
  const cells = [...Array(first).fill(null), ...Array.from({ length: days }, (_, i) => i + 1)];
  const fmt = (d) => `${view.y}/${String(view.m + 1).padStart(2, '0')}/${String(d).padStart(2, '0')}`;
  const move = (delta) => setView((v) => {
    let m = v.m + delta, y = v.y;
    if (m < 0) { m = 11; y--; } if (m > 11) { m = 0; y++; }
    return { y, m };
  });
  return (
    <div className={`ev2-date${open ? ' ev2-date--open' : ''}`} ref={ref}>
      <button type="button" className="ev2-date__trigger" onClick={() => setOpen((o) => !o)} aria-haspopup="dialog" aria-expanded={open}>
        {value ? <span>{value}</span> : <span className="ev2-date__ph">{placeholder}</span>}
        <span className="ev2-date__ico">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
        </span>
      </button>
      {open && (
        <div className="ev2-date__pop" role="dialog">
          <div className="ev2-date__nav">
            <button onClick={() => move(-1)} aria-label="Previous month">‹</button>
            <span className="ev2-date__month">{EV2_MONTHS[view.m]} {view.y}</span>
            <button onClick={() => move(1)} aria-label="Next month">›</button>
          </div>
          <div className="ev2-date__grid">
            {EV2_DOW.map((d) => <div className="ev2-date__dow" key={d}>{d}</div>)}
            {cells.map((d, i) => d === null
              ? <span className="ev2-date__day ev2-date__day--empty" key={i}></span>
              : <button key={i} className={`ev2-date__day${value === fmt(d) ? ' ev2-date__day--sel' : ''}`}
                  onClick={() => { onChange && onChange({ detail: { value: fmt(d) } }); setOpen(false); }}>{d}</button>)}
          </div>
        </div>
      )}
    </div>
  );
}
