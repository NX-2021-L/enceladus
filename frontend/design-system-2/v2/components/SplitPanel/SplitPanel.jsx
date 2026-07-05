// Enceladus v2 · SplitPanel — Cloudscape SplitPanel, deep re-brand.
const ev2SpCss = `
.ev2-split{background:var(--enc-surface,#111827);border-top:1px solid var(--v2-panel-border,rgba(61,155,168,.25));font-family:var(--font-body,'Inter',sans-serif);border-radius:var(--v2-panel-radius,8px) var(--v2-panel-radius,8px) 0 0;overflow:hidden}
.ev2-split__handle{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 18px;cursor:ns-resize;border-bottom:1px solid transparent}
.ev2-split--open .ev2-split__handle{border-bottom-color:var(--v2-divider,rgba(61,155,168,.12))}
.ev2-split__grip{display:flex;flex-direction:column;gap:2px;align-items:center;flex:0 0 auto}
.ev2-split__grip span{width:24px;height:2px;background:var(--enc-slate,#2E4D5C);border-radius:1px}
.ev2-split__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;color:var(--enc-seafoam,#C8DDD9);flex:1;text-align:center}
.ev2-split__toggle{appearance:none;border:none;background:none;color:var(--enc-dust,#6B8A94);cursor:pointer;display:flex;transition:color var(--dur-fast,150ms) var(--ease-orbit),transform var(--dur-base,200ms) var(--ease-orbit)}
.ev2-split__toggle:hover{color:var(--enc-teal-light,#7AC8D4)}
.ev2-split--open .ev2-split__toggle{transform:rotate(180deg)}
.ev2-split__body{padding:16px 18px;font-size:13.5px;line-height:1.6;color:var(--enc-starlight,#EEF2F7)}
.ev2-split__body--closed{display:none}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-sp-css')){const s=document.createElement('style');s.id='ev2-sp-css';s.textContent=ev2SpCss;document.head.appendChild(s);}})();

export function SplitPanel({ header, defaultOpen = true, open, onToggle, children }) {
  const [internal, setInternal] = React.useState(defaultOpen);
  const isOpen = open !== undefined ? open : internal;
  const toggle = () => { const n = !isOpen; if (open === undefined) setInternal(n); onToggle && onToggle({ detail: { open: n } }); };
  return (
    <div className={`ev2-split${isOpen ? ' ev2-split--open' : ''}`}>
      <div className="ev2-split__handle" onClick={toggle}>
        <span className="ev2-split__grip" aria-hidden="true"><span></span><span></span></span>
        <span className="ev2-split__title">{header}</span>
        <button className="ev2-split__toggle" aria-label={isOpen ? 'Collapse' : 'Expand'} aria-expanded={isOpen}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="18 15 12 9 6 15"/></svg>
        </button>
      </div>
      <div className={`ev2-split__body${isOpen ? '' : ' ev2-split__body--closed'}`}>{children}</div>
    </div>
  );
}
