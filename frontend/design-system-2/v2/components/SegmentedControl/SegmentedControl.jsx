// Enceladus v2 · SegmentedControl — Cloudscape SegmentedControl, deep re-brand.
const ev2SegCss = `
.ev2-seg{display:inline-flex;padding:2px;background:var(--v2-field-bg,#0D1220);border:1px solid var(--v2-field-border,rgba(61,155,168,.25));border-radius:var(--v2-control-radius,6px);gap:2px}
.ev2-seg__btn{appearance:none;border:none;background:none;padding:5px 14px;border-radius:4px;font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:13px;color:var(--enc-dust,#6B8A94);cursor:pointer;transition:background var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),color var(--dur-fast,150ms) var(--ease-orbit);white-space:nowrap}
.ev2-seg__btn:hover:not(.ev2-seg__btn--sel){color:var(--enc-teal-light,#7AC8D4)}
.ev2-seg__btn--sel{background:var(--enc-teal,#3D9BA8);color:var(--enc-void,#0A0A0F)}
.ev2-seg__btn:disabled{opacity:.4;cursor:not-allowed}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-seg-css')){const s=document.createElement('style');s.id='ev2-seg-css';s.textContent=ev2SegCss;document.head.appendChild(s);}})();

export function SegmentedControl({ selectedId, options = [], onChange }) {
  return (
    <div className="ev2-seg" role="group">
      {options.map((opt) => (
        <button key={opt.id} type="button" disabled={opt.disabled}
          className={`ev2-seg__btn${opt.id === selectedId ? ' ev2-seg__btn--sel' : ''}`}
          aria-pressed={opt.id === selectedId}
          onClick={() => onChange && onChange({ detail: { selectedId: opt.id } })}>
          {opt.text}
        </button>
      ))}
    </div>
  );
}
