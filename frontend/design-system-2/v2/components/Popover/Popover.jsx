// Enceladus v2 · Popover — Cloudscape Popover, deep re-brand.
const ev2PopCss = `
.ev2-pop{position:relative;display:inline-block;font-family:var(--font-body,'Inter',sans-serif)}
.ev2-pop__trigger{cursor:pointer;border-bottom:1px dashed rgba(122,200,212,.5);color:var(--enc-teal-light,#7AC8D4)}
.ev2-pop__panel{position:absolute;z-index:30;bottom:calc(100% + 8px);left:50%;transform:translateX(-50%);min-width:200px;max-width:300px;background:var(--enc-surface,#111827);border:1px solid var(--v2-panel-border,rgba(61,155,168,.3));border-radius:var(--v2-panel-radius,8px);box-shadow:var(--v2-dropdown-shadow,0 8px 32px rgba(0,0,0,.6));animation:ev2-pop-in var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
@keyframes ev2-pop-in{from{opacity:0;transform:translateX(-50%) translateY(4px)}to{opacity:1;transform:translateX(-50%)}}
.ev2-pop__arrow{position:absolute;top:100%;left:50%;transform:translateX(-50%);width:0;height:0;border:6px solid transparent;border-top-color:var(--enc-surface,#111827)}
.ev2-pop__head{padding:9px 14px;border-bottom:1px solid var(--v2-divider,rgba(61,155,168,.12));font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:13px;color:var(--enc-seafoam,#C8DDD9)}
.ev2-pop__body{padding:11px 14px;font-size:13px;line-height:1.55;color:var(--enc-starlight,#EEF2F7)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-pop-css')){const s=document.createElement('style');s.id='ev2-pop-css';s.textContent=ev2PopCss;document.head.appendChild(s);}})();

export function Popover({ header, content, triggerType = 'text', dismissButton = true, children }) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!open) return;
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);
  return (
    <span className="ev2-pop" ref={ref}>
      <span className={triggerType === 'text' ? 'ev2-pop__trigger' : ''} onClick={() => setOpen((o) => !o)} role="button" tabIndex={0}>{children}</span>
      {open && (
        <span className="ev2-pop__panel" role="dialog">
          {header && <span className="ev2-pop__head" style={{ display: 'block' }}>{header}</span>}
          <span className="ev2-pop__body" style={{ display: 'block' }}>{content}</span>
          <span className="ev2-pop__arrow" aria-hidden="true"></span>
        </span>
      )}
    </span>
  );
}
