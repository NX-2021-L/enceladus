// Enceladus v2 · Drawer — Cloudscape Drawer, deep re-brand.
const ev2DrawerCss = `
.ev2-drawer{display:flex;flex-direction:column;background:var(--enc-surface,#111827);border-left:1px solid var(--v2-panel-border,rgba(61,155,168,.25));font-family:var(--font-body,'Inter',sans-serif);height:100%;box-sizing:border-box;min-width:300px}
.ev2-drawer__head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px 20px;border-bottom:1px solid var(--v2-divider,rgba(61,155,168,.12));flex:0 0 auto}
.ev2-drawer__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:15px;color:var(--enc-seafoam,#C8DDD9);display:flex;align-items:baseline;gap:8px}
.ev2-drawer__rid{font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-teal,#3D9BA8);font-weight:400}
.ev2-drawer__close{appearance:none;border:none;background:none;color:var(--enc-dust,#6B8A94);cursor:pointer;font-size:16px;padding:4px 6px;border-radius:4px;transition:color var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-drawer__close:hover{color:var(--enc-starlight,#EEF2F7)}
.ev2-drawer__body{padding:18px 20px;overflow-y:auto;flex:1;font-size:13.5px;line-height:1.6;color:var(--enc-starlight,#EEF2F7)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-drawer-css')){const s=document.createElement('style');s.id='ev2-drawer-css';s.textContent=ev2DrawerCss;document.head.appendChild(s);}})();

export function Drawer({ header, recordId, onClose, children }) {
  return (
    <aside className="ev2-drawer" aria-label="Drawer">
      <div className="ev2-drawer__head">
        <span className="ev2-drawer__title">{header}{recordId && <span className="ev2-drawer__rid">{recordId}</span>}</span>
        {onClose && <button className="ev2-drawer__close" aria-label="Close" onClick={onClose}>✕</button>}
      </div>
      <div className="ev2-drawer__body">{children}</div>
    </aside>
  );
}
