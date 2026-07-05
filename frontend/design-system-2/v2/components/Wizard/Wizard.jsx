// Enceladus v2 · Wizard — Cloudscape Wizard, deep re-brand.
const ev2WizCss = `
.ev2-wiz{display:grid;grid-template-columns:200px 1fr;gap:28px;font-family:var(--font-body,'Inter',sans-serif)}
.ev2-wiz__nav{display:flex;flex-direction:column;gap:2px}
.ev2-wiz__step{display:flex;gap:11px;padding:8px 6px;border-radius:6px;cursor:pointer;transition:background var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-wiz__step:hover{background:rgba(61,155,168,.05)}
.ev2-wiz__num{width:22px;height:22px;border-radius:50%;flex:0 0 auto;display:flex;align-items:center;justify-content:center;font-family:var(--font-mono,monospace);font-size:11px;border:1.5px solid var(--enc-slate,#2E4D5C);color:var(--enc-dust,#6B8A94);background:var(--enc-void,#0A0A0F)}
.ev2-wiz__step--active .ev2-wiz__num{border-color:var(--enc-teal,#3D9BA8);color:var(--enc-teal,#3D9BA8)}
.ev2-wiz__step--done .ev2-wiz__num{background:var(--enc-teal,#3D9BA8);border-color:var(--enc-teal,#3D9BA8);color:var(--enc-void,#0A0A0F)}
.ev2-wiz__num svg{width:11px;height:11px}
.ev2-wiz__meta{min-width:0}
.ev2-wiz__label{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--enc-dust,#6B8A94)}
.ev2-wiz__title{font-size:13px;color:var(--enc-starlight,#EEF2F7);font-weight:500;margin-top:1px}
.ev2-wiz__step--active .ev2-wiz__title{color:var(--enc-teal-light,#7AC8D4)}
.ev2-wiz__panel{min-width:0}
.ev2-wiz__panel-title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:20px;color:var(--enc-seafoam,#C8DDD9);margin:0 0 16px}
.ev2-wiz__foot{display:flex;justify-content:flex-end;gap:10px;margin-top:24px;padding-top:18px;border-top:1px solid var(--v2-divider,rgba(61,155,168,.12))}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-wiz-css')){const s=document.createElement('style');s.id='ev2-wiz-css';s.textContent=ev2WizCss;document.head.appendChild(s);}})();

export function Wizard({ steps = [], activeStepIndex = 0, onNavigate, onCancel, onSubmit }) {
  const NS = (typeof window !== 'undefined' && window.EnceladusDesignSystem_7eb1fe) || {};
  const Btn = NS.Button || (({ children, ...p }) => <button {...p}>{children}</button>);
  const go = (i) => onNavigate && onNavigate({ detail: { requestedStepIndex: i } });
  const last = activeStepIndex === steps.length - 1;
  const step = steps[activeStepIndex] || {};
  return (
    <div className="ev2-wiz">
      <div className="ev2-wiz__nav">
        {steps.map((s, i) => {
          const state = i < activeStepIndex ? 'done' : i === activeStepIndex ? 'active' : 'pending';
          return (
            <div key={i} className={`ev2-wiz__step ev2-wiz__step--${state}`} onClick={() => i < activeStepIndex && go(i)}>
              <span className="ev2-wiz__num">{state === 'done'
                ? <svg viewBox="0 0 24 24" fill="none" stroke="var(--enc-void,#0A0A0F)" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 12 10 18 20 6"/></svg>
                : i + 1}</span>
              <span className="ev2-wiz__meta">
                <span className="ev2-wiz__label">Step {i + 1}</span>
                <div className="ev2-wiz__title">{s.title}</div>
              </span>
            </div>
          );
        })}
      </div>
      <div className="ev2-wiz__panel">
        <h2 className="ev2-wiz__panel-title">{step.title}</h2>
        <div>{step.content}</div>
        <div className="ev2-wiz__foot">
          <Btn variant="link" onClick={() => onCancel && onCancel()}>Cancel</Btn>
          {activeStepIndex > 0 && <Btn onClick={() => go(activeStepIndex - 1)}>Previous</Btn>}
          {last
            ? <Btn variant="primary" onClick={() => onSubmit && onSubmit()}>Submit</Btn>
            : <Btn variant="primary" onClick={() => go(activeStepIndex + 1)}>Next</Btn>}
        </div>
      </div>
    </div>
  );
}
