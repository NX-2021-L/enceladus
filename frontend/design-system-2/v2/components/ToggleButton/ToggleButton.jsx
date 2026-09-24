// Enceladus v2 · ToggleButton — Cloudscape ToggleButton, deep re-brand.
const ev2TbCss = `
.ev2-tb{display:inline-flex;align-items:center;gap:7px;height:var(--v2-control-height,32px);padding:0 13px;border-radius:var(--v2-control-radius,6px);font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;cursor:pointer;border:1px solid var(--v2-field-border,rgba(61,155,168,.3));background:var(--v2-field-bg,#0D1220);color:var(--enc-dust,#6B8A94);transition:all var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-tb:hover:not(:disabled){color:var(--enc-teal-light,#7AC8D4);border-color:rgba(61,155,168,.5)}
.ev2-tb--pressed{background:rgba(61,155,168,.15);border-color:var(--enc-teal,#3D9BA8);color:var(--enc-teal-light,#7AC8D4)}
.ev2-tb:disabled{opacity:.4;cursor:not-allowed}
.ev2-tb svg{width:15px;height:15px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-tb-css')){const s=document.createElement('style');s.id='ev2-tb-css';s.textContent=ev2TbCss;document.head.appendChild(s);}})();

export function ToggleButton({ pressed = false, disabled = false, iconOn, iconOff, onChange, children }) {
  return (
    <button className={`ev2-tb${pressed ? ' ev2-tb--pressed' : ''}`} disabled={disabled} aria-pressed={pressed}
      onClick={() => onChange && onChange({ detail: { pressed: !pressed } })}>
      {pressed ? iconOn : (iconOff || iconOn)}
      {children}
    </button>
  );
}
