// Enceladus v2 · Checkbox — Cloudscape Checkbox, deep re-brand.
const ev2CheckboxCss = `
.ev2-checkbox{display:inline-flex;align-items:flex-start;gap:9px;cursor:pointer;font-family:var(--font-body,'Inter',sans-serif);font-size:14px;color:var(--enc-starlight,#EEF2F7);line-height:1.4}
.ev2-checkbox--disabled{opacity:.45;cursor:not-allowed}
.ev2-checkbox__box{flex:0 0 auto;width:16px;height:16px;margin-top:1px;border:1px solid var(--v2-field-border,rgba(61,155,168,.4));border-radius:3px;background:var(--v2-field-bg,#0D1220);display:flex;align-items:center;justify-content:center;transition:all var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-checkbox:hover .ev2-checkbox__box{border-color:var(--enc-teal,#3D9BA8)}
.ev2-checkbox--checked .ev2-checkbox__box,.ev2-checkbox--indeterminate .ev2-checkbox__box{background:var(--enc-teal,#3D9BA8);border-color:var(--enc-teal,#3D9BA8)}
.ev2-checkbox__box svg{width:11px;height:11px;stroke:var(--enc-void,#0A0A0F);stroke-width:3;fill:none}
.ev2-checkbox__box--dash{width:8px;height:2px;background:var(--enc-void,#0A0A0F);border-radius:1px}
.ev2-checkbox input{position:absolute;opacity:0;width:0;height:0}
.ev2-checkbox__desc{font-size:12px;color:var(--enc-dust,#6B8A94);margin-top:2px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-checkbox-css')){const s=document.createElement('style');s.id='ev2-checkbox-css';s.textContent=ev2CheckboxCss;document.head.appendChild(s);}})();

export function Checkbox({ checked = false, indeterminate = false, disabled = false, description, onChange, children }) {
  const cls = [
    'ev2-checkbox',
    checked ? 'ev2-checkbox--checked' : '',
    indeterminate ? 'ev2-checkbox--indeterminate' : '',
    disabled ? 'ev2-checkbox--disabled' : '',
  ].filter(Boolean).join(' ');
  return (
    <label className={cls}>
      <input type="checkbox" checked={checked} disabled={disabled}
        onChange={(e) => onChange && onChange({ detail: { checked: e.target.checked } })} />
      <span className="ev2-checkbox__box" aria-hidden="true">
        {indeterminate ? <span className="ev2-checkbox__box--dash"></span>
          : checked ? <svg viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 12 10 18 20 6" /></svg>
          : null}
      </span>
      <span>
        {children}
        {description && <span className="ev2-checkbox__desc" style={{ display: 'block' }}>{description}</span>}
      </span>
    </label>
  );
}
