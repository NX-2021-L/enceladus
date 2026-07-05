// Enceladus v2 · Form — Cloudscape Form, deep re-brand.
const ev2FormCss = `
.ev2-form{font-family:var(--font-body,'Inter',sans-serif)}
.ev2-form__header{margin-bottom:18px}
.ev2-form__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:22px;color:var(--enc-seafoam,#C8DDD9);margin:0 0 5px}
.ev2-form__desc{font-size:13.5px;line-height:1.6;color:var(--enc-dust,#6B8A94);margin:0}
.ev2-form__body{display:flex;flex-direction:column;gap:18px}
.ev2-form__error{margin-top:18px}
.ev2-form__actions{display:flex;justify-content:flex-end;gap:10px;margin-top:22px;padding-top:18px;border-top:1px solid var(--v2-divider,rgba(61,155,168,.12))}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-form-css')){const s=document.createElement('style');s.id='ev2-form-css';s.textContent=ev2FormCss;document.head.appendChild(s);}})();

export function Form({ header, description, errorText, actions, children }) {
  const NS = (typeof window !== 'undefined' && window.EnceladusDesignSystem_7eb1fe) || {};
  return (
    <div className="ev2-form">
      {(header || description) && (
        <div className="ev2-form__header">
          {header && <h2 className="ev2-form__title">{header}</h2>}
          {description && <p className="ev2-form__desc">{description}</p>}
        </div>
      )}
      <div className="ev2-form__body">{children}</div>
      {errorText && (
        <div className="ev2-form__error">
          {NS.Alert ? <NS.Alert type="error" header="Submission blocked">{errorText}</NS.Alert>
            : <div style={{ color: '#C85060', fontSize: 13 }}>{errorText}</div>}
        </div>
      )}
      {actions && <div className="ev2-form__actions">{actions}</div>}
    </div>
  );
}
