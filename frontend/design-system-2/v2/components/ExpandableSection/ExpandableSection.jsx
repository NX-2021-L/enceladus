// Enceladus v2 · ExpandableSection — Cloudscape ExpandableSection, deep re-brand.
const ev2ExpCss = `
.ev2-exp{font-family:var(--font-body,'Inter',sans-serif);border:1px solid var(--v2-panel-border,rgba(61,155,168,.2));border-radius:var(--v2-panel-radius,8px);background:var(--enc-surface,#111827);overflow:hidden}
.ev2-exp--footer{border:none;background:none}
.ev2-exp__trigger{display:flex;align-items:center;gap:10px;width:100%;padding:12px 16px;background:none;border:none;cursor:pointer;text-align:left;color:var(--enc-seafoam,#C8DDD9);font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;transition:background var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-exp__trigger:hover{background:rgba(61,155,168,.05)}
.ev2-exp__chev{color:var(--enc-teal,#3D9BA8);transition:transform var(--dur-base,200ms) var(--ease-orbit);flex:0 0 auto;display:flex}
.ev2-exp--open .ev2-exp__chev{transform:rotate(90deg)}
.ev2-exp__count{margin-left:auto;font-family:var(--font-mono,monospace);font-size:12px;color:var(--enc-dust,#6B8A94);font-weight:400}
.ev2-exp__body{padding:0 16px 14px 40px;font-size:13.5px;line-height:1.6;color:var(--enc-starlight,#EEF2F7)}
.ev2-exp__body--closed{display:none}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-exp-css')){const s=document.createElement('style');s.id='ev2-exp-css';s.textContent=ev2ExpCss;document.head.appendChild(s);}})();

export function ExpandableSection({ headerText, headerCounter, variant = 'default', defaultExpanded = false, expanded, onChange, children }) {
  const [internal, setInternal] = React.useState(defaultExpanded);
  const isOpen = expanded !== undefined ? expanded : internal;
  const toggle = () => {
    const next = !isOpen;
    if (expanded === undefined) setInternal(next);
    onChange && onChange({ detail: { expanded: next } });
  };
  return (
    <div className={`ev2-exp${variant === 'footer' ? ' ev2-exp--footer' : ''}${isOpen ? ' ev2-exp--open' : ''}`}>
      <button className="ev2-exp__trigger" aria-expanded={isOpen} onClick={toggle}>
        <span className="ev2-exp__chev" aria-hidden="true">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
        </span>
        {headerText}
        {headerCounter && <span className="ev2-exp__count">{headerCounter}</span>}
      </button>
      <div className={`ev2-exp__body${isOpen ? '' : ' ev2-exp__body--closed'}`}>{children}</div>
    </div>
  );
}
