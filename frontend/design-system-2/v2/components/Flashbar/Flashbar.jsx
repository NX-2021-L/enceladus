// Enceladus v2 · Flashbar — Cloudscape Flashbar, deep re-brand.
const ev2FlashbarCss = `
.ev2-flashbar{display:flex;flex-direction:column;gap:8px}
.ev2-flash{display:flex;gap:12px;align-items:flex-start;padding:12px 16px;border-radius:var(--v2-panel-radius,8px);font-family:var(--font-body,'Inter',sans-serif);font-size:14px;line-height:1.5;color:var(--enc-void,#0A0A0F);animation:ev2-flash-in var(--dur-slow,300ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
@keyframes ev2-flash-in{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion: reduce){.ev2-flash{animation:none}}
.ev2-flash--success{background:var(--enc-teal,#3D9BA8)}
.ev2-flash--error{background:var(--enc-crimson,#C85060);color:var(--enc-starlight,#EEF2F7)}
.ev2-flash--warning{background:var(--v2-status-warning,#C9A15C)}
.ev2-flash--info{background:var(--enc-surface-alt,#1C2333);color:var(--enc-starlight,#EEF2F7);border:1px solid rgba(122,200,212,.3)}
.ev2-flash--in-progress{background:var(--enc-surface-alt,#1C2333);color:var(--enc-starlight,#EEF2F7);border:1px solid rgba(122,200,212,.3)}
.ev2-flash__header{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;margin:0 0 2px}
.ev2-flash__body{flex:1;min-width:0}
.ev2-flash__rid{font-family:var(--font-mono,monospace);font-size:11.5px;opacity:.8;margin-left:8px}
.ev2-flash__dismiss{background:none;border:none;color:inherit;opacity:.7;cursor:pointer;font-size:15px;line-height:1;padding:2px 4px;transition:opacity var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-flash__dismiss:hover{opacity:1}
@keyframes ev2-flash-spin{to{transform:rotate(360deg)}}
.ev2-flash__spinner{width:14px;height:14px;margin-top:2px;border-radius:50%;border:2px solid currentColor;border-top-color:transparent;animation:ev2-flash-spin .8s linear infinite;flex:0 0 auto}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-flashbar-css')){const s=document.createElement('style');s.id='ev2-flashbar-css';s.textContent=ev2FlashbarCss;document.head.appendChild(s);}})();

export function Flashbar({ items = [] }) {
  const [dismissed, setDismissed] = React.useState({});
  return (
    <div className="ev2-flashbar">
      {items.filter((it) => !dismissed[it.id]).map((it) => (
        <div key={it.id} className={`ev2-flash ev2-flash--${it.type || 'info'}`} role={it.type === 'error' ? 'alert' : 'status'}>
          {(it.loading || it.type === 'in-progress') && <span className="ev2-flash__spinner" aria-hidden="true"></span>}
          <div className="ev2-flash__body">
            {it.header && <div className="ev2-flash__header">{it.header}{it.recordId && <span className="ev2-flash__rid">{it.recordId}</span>}</div>}
            {it.content}
          </div>
          {it.dismissible && (
            <button className="ev2-flash__dismiss" aria-label="Dismiss"
              onClick={() => { setDismissed((d) => ({ ...d, [it.id]: true })); it.onDismiss && it.onDismiss(); }}>✕</button>
          )}
        </div>
      ))}
    </div>
  );
}
