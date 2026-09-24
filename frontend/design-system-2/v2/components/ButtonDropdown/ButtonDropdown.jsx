// Enceladus v2 · ButtonDropdown — Cloudscape ButtonDropdown, deep re-brand.
const ev2BdCss = `
.ev2-bd{position:relative;display:inline-block;font-family:var(--font-body,'Inter',sans-serif)}
.ev2-bd__trigger{display:inline-flex;align-items:center;gap:8px;height:var(--v2-control-height,32px);padding:0 12px;border-radius:var(--v2-control-radius,6px);font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;cursor:pointer;border:1px solid var(--enc-teal,#3D9BA8);color:var(--enc-teal,#3D9BA8);background:none;transition:all var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-bd__trigger:hover{background:rgba(61,155,168,.08);color:var(--enc-teal-light,#7AC8D4);border-color:var(--enc-teal-light,#7AC8D4)}
.ev2-bd--primary .ev2-bd__trigger{background:var(--enc-teal,#3D9BA8);color:var(--enc-void,#0A0A0F)}
.ev2-bd--primary .ev2-bd__trigger:hover{background:var(--enc-teal-light,#7AC8D4)}
.ev2-bd__chev{transition:transform var(--dur-base,200ms) var(--ease-orbit);display:flex}
.ev2-bd--open .ev2-bd__chev{transform:rotate(180deg)}
.ev2-bd__menu{position:absolute;top:calc(100% + 4px);right:0;z-index:30;min-width:200px;background:var(--enc-surface,#111827);border:1px solid var(--v2-panel-border,rgba(61,155,168,.25));border-radius:var(--v2-panel-radius,8px);box-shadow:var(--v2-dropdown-shadow,0 8px 32px rgba(0,0,0,.6));padding:4px}
.ev2-bd__item{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 11px;border-radius:5px;font-size:13.5px;color:var(--enc-starlight,#EEF2F7);cursor:pointer;transition:background var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-bd__item:hover:not(.ev2-bd__item--disabled){background:rgba(61,155,168,.1)}
.ev2-bd__item--danger{color:var(--enc-crimson,#C85060)}
.ev2-bd__item--disabled{opacity:.4;cursor:not-allowed}
.ev2-bd__item-desc{font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-dust,#6B8A94)}
.ev2-bd__divider{height:1px;background:var(--v2-divider,rgba(61,155,168,.12));margin:4px 2px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-bd-css')){const s=document.createElement('style');s.id='ev2-bd-css';s.textContent=ev2BdCss;document.head.appendChild(s);}})();

export function ButtonDropdown({ items = [], variant = 'normal', disabled = false, onItemClick, children }) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!open) return;
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);
  return (
    <div className={`ev2-bd${variant === 'primary' ? ' ev2-bd--primary' : ''}${open ? ' ev2-bd--open' : ''}`} ref={ref}>
      <button className="ev2-bd__trigger" disabled={disabled} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        {children}
        <span className="ev2-bd__chev" aria-hidden="true">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
        </span>
      </button>
      {open && (
        <div className="ev2-bd__menu" role="menu">
          {items.map((it, i) => it.type === 'divider'
            ? <div className="ev2-bd__divider" key={i}></div>
            : (
              <div key={it.id || i} role="menuitem"
                className={`ev2-bd__item${it.danger ? ' ev2-bd__item--danger' : ''}${it.disabled ? ' ev2-bd__item--disabled' : ''}`}
                onClick={() => { if (!it.disabled) { onItemClick && onItemClick({ detail: { id: it.id } }); setOpen(false); } }}>
                <span>{it.text}</span>
                {it.description && <span className="ev2-bd__item-desc">{it.description}</span>}
              </div>
            ))}
        </div>
      )}
    </div>
  );
}
