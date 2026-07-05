// Enceladus v2 · Select — Cloudscape Select, deep re-brand.
const ev2SelectCss = `
.ev2-select{position:relative;font-family:var(--font-body,'Inter',sans-serif);width:100%}
.ev2-select__trigger{display:flex;align-items:center;justify-content:space-between;gap:8px;width:100%;height:var(--v2-control-height,32px);padding:0 10px 0 12px;background:var(--v2-field-bg,#0D1220);border:1px solid var(--v2-field-border,rgba(61,155,168,.25));border-radius:var(--v2-control-radius,6px);color:var(--enc-starlight,#EEF2F7);font-size:14px;cursor:pointer;transition:border-color var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),box-shadow var(--dur-base,200ms) var(--ease-orbit);box-sizing:border-box;text-align:left}
.ev2-select__trigger:hover{border-color:var(--v2-field-border-hover,rgba(61,155,168,.45))}
.ev2-select--open .ev2-select__trigger{border-color:var(--v2-field-border-focus,#3D9BA8);box-shadow:var(--v2-focus-ring)}
.ev2-select--placeholder .ev2-select__value{color:var(--v2-field-placeholder,#4A5E68)}
.ev2-select__value{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev2-select__chev{flex:0 0 auto;color:var(--enc-dust,#6B8A94);transition:transform var(--dur-base,200ms) var(--ease-orbit)}
.ev2-select--open .ev2-select__chev{transform:rotate(180deg)}
.ev2-select__menu{position:absolute;top:calc(100% + 4px);left:0;right:0;z-index:20;background:var(--enc-surface,#111827);border:1px solid var(--v2-panel-border,rgba(61,155,168,.25));border-radius:var(--v2-panel-radius,8px);box-shadow:var(--v2-dropdown-shadow,0 8px 32px rgba(0,0,0,.6));padding:4px;max-height:240px;overflow-y:auto}
.ev2-select__opt{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:7px 10px;border-radius:4px;cursor:pointer;font-size:14px;color:var(--enc-starlight,#EEF2F7);transition:background var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-select__opt:hover{background:rgba(61,155,168,.1)}
.ev2-select__opt--selected{color:var(--enc-teal-light,#7AC8D4)}
.ev2-select__opt--selected::after{content:'✓';font-family:var(--font-mono,monospace);font-size:12px}
.ev2-select__optdesc{font-size:11.5px;color:var(--enc-dust,#6B8A94);display:block;margin-top:1px}
.ev2-select__tag{font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-dust,#6B8A94)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-select-css')){const s=document.createElement('style');s.id='ev2-select-css';s.textContent=ev2SelectCss;document.head.appendChild(s);}})();

const ev2Chevron = () => React.createElement('svg', { className: 'ev2-select__chev', width: 14, height: 14, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2, strokeLinecap: 'round', strokeLinejoin: 'round' }, React.createElement('polyline', { points: '6 9 12 15 18 9' }));

export function Select({ selectedOption, options = [], placeholder = 'Choose an option', disabled = false, onChange }) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!open) return;
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);
  const cls = ['ev2-select', open ? 'ev2-select--open' : '', !selectedOption ? 'ev2-select--placeholder' : ''].filter(Boolean).join(' ');
  return (
    <div className={cls} ref={ref}>
      <button type="button" className="ev2-select__trigger" disabled={disabled}
        aria-haspopup="listbox" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <span className="ev2-select__value">{selectedOption ? selectedOption.label : placeholder}</span>
        {ev2Chevron()}
      </button>
      {open && (
        <div className="ev2-select__menu" role="listbox">
          {options.map((opt) => {
            const selected = selectedOption && selectedOption.value === opt.value;
            return (
              <div key={opt.value} role="option" aria-selected={selected}
                className={`ev2-select__opt${selected ? ' ev2-select__opt--selected' : ''}`}
                onClick={() => { onChange && onChange({ detail: { selectedOption: opt } }); setOpen(false); }}>
                <span>
                  {opt.label}
                  {opt.description && <span className="ev2-select__optdesc">{opt.description}</span>}
                </span>
                {opt.tag && <span className="ev2-select__tag">{opt.tag}</span>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
