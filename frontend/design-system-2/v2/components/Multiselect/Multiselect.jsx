// Enceladus v2 · Multiselect — Cloudscape Multiselect, deep re-brand.
// ENC-TSK-S63-0C: style string re-skinned onto the v1.1 role tokens (design system artifact 1794603005-04d0); props, events, DOM and class names unchanged.
const ev2MultiCss = `
.ev2-multi{position:relative;font-family:var(--font-body,'Inter',sans-serif);width:100%}
.ev2-multi__trigger{display:flex;align-items:center;gap:6px;flex-wrap:wrap;width:100%;min-height:var(--control-h,32px);padding:3px 10px 3px 8px;background:var(--surface-sunken,#0D1220);border:1px solid var(--tint-teal-25,rgba(61,155,168,.25));border-radius:var(--v2-control-radius,6px);cursor:pointer;transition:border-color var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),box-shadow var(--dur-base,200ms) var(--ease-orbit);box-sizing:border-box}
.ev2-multi__trigger:hover{border-color:var(--tint-teal-45,rgba(61,155,168,.45))}
.ev2-multi--open .ev2-multi__trigger{border-color:var(--focus,#3D9BA8);box-shadow:var(--v2-focus-ring)}
.ev2-multi__ph{color:var(--text-placeholder,#4A5E68);font-size:var(--text-sm,14px);padding:2px 0}
.ev2-multi__chip{display:inline-flex;align-items:center;gap:6px;padding:2px 5px 2px 9px;background:var(--tint-teal-12,rgba(61,155,168,.12));border:1px solid var(--tint-teal-35,rgba(61,155,168,.35));border-radius:4px;font-size:var(--text-xs,12px);color:var(--accent-hover,#7AC8D4)}
.ev2-multi__chip button{appearance:none;border:none;background:none;color:inherit;cursor:pointer;font-size:var(--text-xs,12px);line-height:1;padding:1px 2px;opacity:.7}
.ev2-multi__chip button:hover{opacity:1}
.ev2-multi__chevwrap{margin-left:auto;display:flex;align-items:center;color:var(--text-dim,#6B8A94)}
.ev2-multi__menu{position:absolute;top:calc(100% + 4px);left:0;right:0;z-index:20;background:var(--surface,#111827);border:1px solid var(--border,rgba(61,155,168,.25));border-radius:var(--v2-panel-radius,8px);box-shadow:var(--v2-dropdown-shadow,0 8px 32px rgba(0,0,0,.6));padding:4px;max-height:240px;overflow-y:auto}
.ev2-multi__opt{display:flex;align-items:center;gap:9px;padding:7px 10px;border-radius:4px;cursor:pointer;font-size:var(--text-sm,14px);color:var(--text,#EEF2F7);transition:background var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-multi__opt:hover{background:var(--tint-teal-10,rgba(61,155,168,.1))}
.ev2-multi__cb{width:15px;height:15px;border-radius:3px;border:1px solid var(--tint-teal-25,rgba(61,155,168,.4));display:flex;align-items:center;justify-content:center;flex:0 0 auto}
.ev2-multi__opt--sel .ev2-multi__cb{background:var(--accent,#3D9BA8);border-color:var(--accent,#3D9BA8)}
.ev2-multi__cb svg{width:10px;height:10px;stroke:var(--text-on-accent,#0A0A0F);stroke-width:3;fill:none}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-multi-css')){const s=document.createElement('style');s.id='ev2-multi-css';s.textContent=ev2MultiCss;document.head.appendChild(s);}})();

export function Multiselect({ selectedOptions = [], options = [], placeholder = 'Choose options', onChange }) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!open) return;
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);
  const selValues = selectedOptions.map((o) => o.value);
  const toggle = (opt) => {
    const next = selValues.includes(opt.value)
      ? selectedOptions.filter((o) => o.value !== opt.value)
      : [...selectedOptions, opt];
    onChange && onChange({ detail: { selectedOptions: next } });
  };
  return (
    <div className={`ev2-multi${open ? ' ev2-multi--open' : ''}`} ref={ref}>
      <div className="ev2-multi__trigger" onClick={() => setOpen((o) => !o)} role="button" aria-haspopup="listbox" aria-expanded={open}>
        {selectedOptions.length === 0 && <span className="ev2-multi__ph">{placeholder}</span>}
        {selectedOptions.map((o) => (
          <span key={o.value} className="ev2-multi__chip">
            {o.label}
            <button aria-label={`Remove ${o.label}`} onClick={(e) => { e.stopPropagation(); toggle(o); }}>✕</button>
          </span>
        ))}
        <span className="ev2-multi__chevwrap">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
        </span>
      </div>
      {open && (
        <div className="ev2-multi__menu" role="listbox" aria-multiselectable="true">
          {options.map((opt) => {
            const sel = selValues.includes(opt.value);
            return (
              <div key={opt.value} role="option" aria-selected={sel}
                className={`ev2-multi__opt${sel ? ' ev2-multi__opt--sel' : ''}`} onClick={() => toggle(opt)}>
                <span className="ev2-multi__cb" aria-hidden="true">
                  {sel && <svg viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 12 10 18 20 6"/></svg>}
                </span>
                {opt.label}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
