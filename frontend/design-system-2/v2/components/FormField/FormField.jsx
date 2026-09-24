// Enceladus v2 · FormField — Cloudscape FormField, deep re-brand.
const ev2FormFieldCss = `
.ev2-formfield{font-family:var(--font-body,'Inter',sans-serif)}
.ev2-formfield__label{display:block;font-size:13px;font-weight:600;color:var(--enc-seafoam,#C8DDD9);margin-bottom:4px}
.ev2-formfield__info{margin-left:6px;font-weight:400;font-size:12px;color:var(--enc-dust,#6B8A94)}
.ev2-formfield__desc{font-size:12px;line-height:1.5;color:var(--enc-dust,#6B8A94);margin-bottom:6px}
.ev2-formfield__control{margin-top:2px}
.ev2-formfield__error{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--enc-crimson,#C85060);margin-top:5px}
.ev2-formfield__error::before{content:'';width:6px;height:6px;border-radius:50%;background:currentColor;flex:0 0 auto}
.ev2-formfield__constraint{font-size:11.5px;color:var(--enc-dust,#6B8A94);margin-top:5px;font-family:var(--font-mono,monospace)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-formfield-css')){const s=document.createElement('style');s.id='ev2-formfield-css';s.textContent=ev2FormFieldCss;document.head.appendChild(s);}})();

export function FormField({ label, info, description, errorText, constraintText, children }) {
  return (
    <div className="ev2-formfield">
      {label && <label className="ev2-formfield__label">{label}{info && <span className="ev2-formfield__info">{info}</span>}</label>}
      {description && <div className="ev2-formfield__desc">{description}</div>}
      <div className="ev2-formfield__control">{children}</div>
      {constraintText && <div className="ev2-formfield__constraint">{constraintText}</div>}
      {errorText && <div className="ev2-formfield__error" role="alert">{errorText}</div>}
    </div>
  );
}
