// Enceladus v2 · Toggle — Cloudscape Toggle, deep re-brand.
const ev2ToggleCss = `
.ev2-toggle{display:inline-flex;align-items:center;gap:10px;cursor:pointer;font-family:var(--font-body,'Inter',sans-serif);font-size:14px;color:var(--enc-starlight,#EEF2F7)}
.ev2-toggle--disabled{opacity:.45;cursor:not-allowed}
.ev2-toggle__track{position:relative;width:34px;height:18px;border-radius:9px;background:var(--enc-slate,#2E4D5C);border:1px solid rgba(61,155,168,.3);transition:background var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),border-color var(--dur-base,200ms) var(--ease-orbit);flex:0 0 auto}
.ev2-toggle--on .ev2-toggle__track{background:var(--enc-teal,#3D9BA8);border-color:var(--enc-teal,#3D9BA8)}
.ev2-toggle__knob{position:absolute;top:1px;left:1px;width:14px;height:14px;border-radius:50%;background:var(--enc-starlight,#EEF2F7);transition:transform var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-toggle--on .ev2-toggle__knob{transform:translateX(16px);background:var(--enc-void,#0A0A0F)}
.ev2-toggle input{position:absolute;opacity:0;width:0;height:0}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-toggle-css')){const s=document.createElement('style');s.id='ev2-toggle-css';s.textContent=ev2ToggleCss;document.head.appendChild(s);}})();

export function Toggle({ checked = false, disabled = false, onChange, children }) {
  const cls = ['ev2-toggle', checked ? 'ev2-toggle--on' : '', disabled ? 'ev2-toggle--disabled' : ''].filter(Boolean).join(' ');
  return (
    <label className={cls}>
      <input type="checkbox" role="switch" checked={checked} disabled={disabled}
        onChange={(e) => onChange && onChange({ detail: { checked: e.target.checked } })} />
      <span className="ev2-toggle__track" aria-hidden="true"><span className="ev2-toggle__knob"></span></span>
      {children && <span>{children}</span>}
    </label>
  );
}
