// Enceladus v2 · RadioGroup — Cloudscape RadioGroup, deep re-brand.
const ev2RadioCss = `
.ev2-radiogroup{display:flex;flex-direction:column;gap:10px;font-family:var(--font-body,'Inter',sans-serif)}
.ev2-radio{display:inline-flex;align-items:flex-start;gap:9px;cursor:pointer;font-size:14px;color:var(--enc-starlight,#EEF2F7);line-height:1.4}
.ev2-radio--disabled{opacity:.45;cursor:not-allowed}
.ev2-radio__dot{flex:0 0 auto;width:16px;height:16px;margin-top:1px;border-radius:50%;border:1px solid var(--v2-field-border,rgba(61,155,168,.4));background:var(--v2-field-bg,#0D1220);display:flex;align-items:center;justify-content:center;transition:border-color var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-radio:hover .ev2-radio__dot{border-color:var(--enc-teal,#3D9BA8)}
.ev2-radio--checked .ev2-radio__dot{border-color:var(--enc-teal,#3D9BA8)}
.ev2-radio--checked .ev2-radio__dot::after{content:'';width:8px;height:8px;border-radius:50%;background:var(--enc-teal,#3D9BA8)}
.ev2-radio input{position:absolute;opacity:0;width:0;height:0}
.ev2-radio__desc{font-size:12px;color:var(--enc-dust,#6B8A94);margin-top:2px;display:block}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-radio-css')){const s=document.createElement('style');s.id='ev2-radio-css';s.textContent=ev2RadioCss;document.head.appendChild(s);}})();

export function RadioGroup({ value, items = [], onChange, name }) {
  const groupName = name || React.useId();
  return (
    <div className="ev2-radiogroup" role="radiogroup">
      {items.map((it) => {
        const checked = it.value === value;
        const cls = ['ev2-radio', checked ? 'ev2-radio--checked' : '', it.disabled ? 'ev2-radio--disabled' : ''].filter(Boolean).join(' ');
        return (
          <label key={it.value} className={cls}>
            <input type="radio" name={groupName} checked={checked} disabled={it.disabled}
              onChange={() => onChange && onChange({ detail: { value: it.value } })} />
            <span className="ev2-radio__dot" aria-hidden="true"></span>
            <span>
              {it.label}
              {it.description && <span className="ev2-radio__desc">{it.description}</span>}
            </span>
          </label>
        );
      })}
    </div>
  );
}
