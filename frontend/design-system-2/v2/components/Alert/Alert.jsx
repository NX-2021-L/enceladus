// Enceladus v2 · Alert — Cloudscape Alert, deep re-brand.
// ENC-TSK-S62-0B: colors read the v1.1 alert roles (info, success, warning, danger).
const ev2AlertCss = `
.ev2-alert{display:flex;gap:12px;padding:14px 16px;border-radius:var(--v2-panel-radius,8px);border:1px solid;border-left-width:3px;font-family:var(--font-body,'Inter',sans-serif);font-size:14px;line-height:1.55;color:var(--enc-starlight,#EEF2F7);min-width:0;max-width:100%;box-sizing:border-box}
.ev2-alert--info{background:var(--tint-blue-08,rgba(127,176,255,.08));border-color:var(--tint-blue-45,rgba(127,176,255,.45));border-left-color:var(--info,#4F8DF0)}
.ev2-alert--success{background:var(--tint-green-14,rgba(141,232,184,.14));border-color:var(--tint-green-45,rgba(141,232,184,.45));border-left-color:var(--success,#3FBF85)}
.ev2-alert--warning{background:var(--tint-amber-10,rgba(201,161,92,.1));border-color:var(--tint-amber-40,rgba(201,161,92,.4));border-left-color:var(--warning,#C9A15C)}
.ev2-alert--error{background:var(--tint-red-14,rgba(245,139,147,.14));border-color:color-mix(in srgb,var(--danger,#C85060) 45%,transparent);border-left-color:var(--danger,#C85060)}
.ev2-alert__body{flex:1;min-width:0;overflow-wrap:anywhere}
.ev2-alert__header{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:14px;margin:0 0 3px;color:var(--enc-seafoam,#C8DDD9)}
.ev2-alert__dot{width:9px;height:9px;border-radius:50%;margin-top:5px;flex:0 0 auto}
.ev2-alert--info .ev2-alert__dot{background:var(--info,#4F8DF0)}
.ev2-alert--success .ev2-alert__dot{background:var(--success,#3FBF85)}
.ev2-alert--warning .ev2-alert__dot{background:var(--warning,#C9A15C)}
.ev2-alert--error .ev2-alert__dot{background:var(--danger,#C85060)}
.ev2-alert__dismiss{background:none;border:none;color:var(--enc-dust,#6B8A94);cursor:pointer;font-size:16px;line-height:1;padding:2px 4px;border-radius:4px;transition:color var(--dur-fast,150ms) var(--ease-orbit);align-self:flex-start}
.ev2-alert__dismiss:hover{color:var(--enc-starlight,#EEF2F7)}
.ev2-alert__action{margin-top:10px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-alert-css')){const s=document.createElement('style');s.id='ev2-alert-css';s.textContent=ev2AlertCss;document.head.appendChild(s);}})();

export function Alert({ type = 'info', header, dismissible = false, onDismiss, action, children }) {
  const [visible, setVisible] = React.useState(true);
  if (!visible) return null;
  return (
    <div className={`ev2-alert ev2-alert--${type}`} role={type === 'error' ? 'alert' : 'status'}>
      <span className="ev2-alert__dot" aria-hidden="true"></span>
      <div className="ev2-alert__body">
        {header && <div className="ev2-alert__header">{header}</div>}
        <div>{children}</div>
        {action && <div className="ev2-alert__action">{action}</div>}
      </div>
      {dismissible && (
        <button className="ev2-alert__dismiss" aria-label="Dismiss"
          onClick={() => { setVisible(false); onDismiss && onDismiss(); }}>✕</button>
      )}
    </div>
  );
}
