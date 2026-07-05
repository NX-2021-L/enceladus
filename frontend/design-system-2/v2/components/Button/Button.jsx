// Enceladus v2 · Button — Cloudscape Button, deep re-brand.
const ev2ButtonCss = `
.ev2-btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;height:var(--v2-control-height,32px);padding:0 var(--v2-control-padding-x,16px);border-radius:var(--v2-control-radius,6px);font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;line-height:1;cursor:pointer;transition:all var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1));border:1px solid transparent;background:transparent;white-space:nowrap;text-decoration:none}
.ev2-btn:focus-visible{outline:none;box-shadow:var(--v2-focus-ring)}
.ev2-btn--primary{background:var(--enc-teal,#3D9BA8);color:var(--enc-void,#0A0A0F)}
.ev2-btn--primary:hover:not(:disabled){background:var(--enc-teal-light,#7AC8D4)}
.ev2-btn--normal{border-color:var(--enc-teal,#3D9BA8);color:var(--enc-teal,#3D9BA8)}
.ev2-btn--normal:hover:not(:disabled){border-color:var(--enc-teal-light,#7AC8D4);color:var(--enc-teal-light,#7AC8D4);background:rgba(61,155,168,.08)}
.ev2-btn--danger{border-color:rgba(200,80,96,.6);color:var(--enc-crimson,#C85060)}
.ev2-btn--danger:hover:not(:disabled){background:rgba(200,80,96,.1);border-color:var(--enc-crimson,#C85060)}
.ev2-btn--link{color:var(--enc-teal-light,#7AC8D4);padding:0 4px}
.ev2-btn--link:hover:not(:disabled){color:var(--enc-seafoam,#C8DDD9);text-decoration:underline}
.ev2-btn--icon{padding:0 8px;color:var(--enc-dust,#6B8A94)}
.ev2-btn--icon:hover:not(:disabled){color:var(--enc-teal-light,#7AC8D4)}
.ev2-btn:disabled{opacity:.4;cursor:not-allowed}
.ev2-btn__rid{font-family:var(--font-mono,monospace);font-size:11px;opacity:.75}
@keyframes ev2-btn-spin{to{transform:rotate(360deg)}}
.ev2-btn__spinner{width:13px;height:13px;border-radius:50%;border:2px solid currentColor;border-top-color:transparent;animation:ev2-btn-spin .8s linear infinite}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-button-css')){const s=document.createElement('style');s.id='ev2-button-css';s.textContent=ev2ButtonCss;document.head.appendChild(s);}})();

export function Button({ variant = 'normal', disabled = false, loading = false, href, onClick, recordId, ariaLabel, children }) {
  const cls = `ev2-btn ev2-btn--${variant}`;
  const content = (
    <React.Fragment>
      {loading && <span className="ev2-btn__spinner" aria-hidden="true"></span>}
      {children}
      {recordId && <span className="ev2-btn__rid">{recordId}</span>}
    </React.Fragment>
  );
  if (href && !disabled) {
    return <a className={cls} href={href} aria-label={ariaLabel}>{content}</a>;
  }
  return (
    <button className={cls} disabled={disabled || loading} onClick={onClick} aria-label={ariaLabel}>
      {content}
    </button>
  );
}
