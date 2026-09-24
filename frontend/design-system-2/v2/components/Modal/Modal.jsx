// Enceladus v2 · Modal — Cloudscape Modal, deep re-brand.
const ev2ModalCss = `
.ev2-modal__overlay{position:fixed;inset:0;z-index:100;background:var(--v2-overlay-bg,rgba(10,10,15,.85));backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:24px;animation:ev2-modal-fade var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
@keyframes ev2-modal-fade{from{opacity:0}to{opacity:1}}
.ev2-modal{background:var(--enc-surface,#111827);border:1px solid var(--v2-panel-border,rgba(61,155,168,.25));border-radius:var(--v2-panel-radius,8px);box-shadow:var(--v2-dropdown-shadow,0 8px 32px rgba(0,0,0,.6));width:100%;display:flex;flex-direction:column;max-height:85vh;font-family:var(--font-body,'Inter',sans-serif);animation:ev2-modal-rise var(--dur-slow,300ms) var(--ease-orbit)}
@keyframes ev2-modal-rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion: reduce){.ev2-modal,.ev2-modal__overlay{animation:none}}
.ev2-modal--small{max-width:400px}.ev2-modal--medium{max-width:600px}.ev2-modal--large{max-width:820px}
.ev2-modal__head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:18px 22px;border-bottom:1px solid var(--v2-divider,rgba(61,155,168,.12));flex:0 0 auto}
.ev2-modal__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:18px;color:var(--enc-seafoam,#C8DDD9);margin:0;display:flex;align-items:baseline;gap:9px}
.ev2-modal__rid{font-family:var(--font-mono,monospace);font-size:12px;color:var(--enc-teal,#3D9BA8);font-weight:400}
.ev2-modal__close{appearance:none;border:none;background:none;color:var(--enc-dust,#6B8A94);cursor:pointer;font-size:17px;padding:2px 6px;border-radius:4px;transition:color var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-modal__close:hover{color:var(--enc-starlight,#EEF2F7)}
.ev2-modal__body{padding:20px 22px;overflow-y:auto;font-size:14px;line-height:1.6;color:var(--enc-starlight,#EEF2F7);flex:1}
.ev2-modal__foot{display:flex;justify-content:flex-end;gap:10px;padding:14px 22px;border-top:1px solid var(--v2-divider,rgba(61,155,168,.12));flex:0 0 auto}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-modal-css')){const s=document.createElement('style');s.id='ev2-modal-css';s.textContent=ev2ModalCss;document.head.appendChild(s);}})();

export function Modal({ visible = false, header, recordId, size = 'medium', footer, onDismiss, children }) {
  React.useEffect(() => {
    if (!visible) return;
    const h = (e) => { if (e.key === 'Escape') onDismiss && onDismiss(); };
    document.addEventListener('keydown', h);
    return () => document.removeEventListener('keydown', h);
  }, [visible, onDismiss]);
  if (!visible) return null;
  return (
    <div className="ev2-modal__overlay" onClick={(e) => { if (e.target === e.currentTarget) onDismiss && onDismiss(); }}>
      <div className={`ev2-modal ev2-modal--${size}`} role="dialog" aria-modal="true">
        <div className="ev2-modal__head">
          <h2 className="ev2-modal__title">{header}{recordId && <span className="ev2-modal__rid">{recordId}</span>}</h2>
          <button className="ev2-modal__close" aria-label="Close" onClick={() => onDismiss && onDismiss()}>✕</button>
        </div>
        <div className="ev2-modal__body">{children}</div>
        {footer && <div className="ev2-modal__foot">{footer}</div>}
      </div>
    </div>
  );
}
