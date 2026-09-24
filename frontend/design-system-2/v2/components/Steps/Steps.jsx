// Enceladus v2 · Steps — Cloudscape Steps, deep re-brand (progress/execution steps).
const ev2StepsCss = `
.ev2-steps{font-family:var(--font-body,'Inter',sans-serif);display:flex;flex-direction:column}
.ev2-step{display:flex;gap:12px;position:relative}
.ev2-step__rail{display:flex;flex-direction:column;align-items:center;flex:0 0 auto}
.ev2-step__marker{width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex:0 0 auto;border:1.5px solid var(--enc-slate,#2E4D5C);background:var(--enc-void,#0A0A0F);z-index:1}
.ev2-step__marker svg{width:11px;height:11px}
.ev2-step--success .ev2-step__marker{background:var(--enc-teal,#3D9BA8);border-color:var(--enc-teal,#3D9BA8)}
.ev2-step--error .ev2-step__marker{background:var(--enc-crimson,#C85060);border-color:var(--enc-crimson,#C85060)}
.ev2-step--loading .ev2-step__marker{border-color:var(--enc-teal,#3D9BA8)}
.ev2-step__line{width:1.5px;flex:1;background:var(--enc-slate,#2E4D5C);margin:2px 0}
.ev2-step--success .ev2-step__line{background:var(--enc-teal,#3D9BA8)}
.ev2-step:last-child .ev2-step__line{display:none}
.ev2-step__content{padding-bottom:16px;flex:1;min-width:0}
.ev2-step__header{font-size:14px;font-weight:500;color:var(--enc-starlight,#EEF2F7);line-height:1.3}
.ev2-step--pending .ev2-step__header{color:var(--enc-dust,#6B8A94)}
.ev2-step__detail{font-size:12.5px;color:var(--enc-dust,#6B8A94);margin-top:2px;font-family:var(--font-mono,monospace)}
@keyframes ev2-steps-spin{to{transform:rotate(360deg)}}
.ev2-step__spin{width:12px;height:12px;border-radius:50%;border:2px solid var(--enc-teal,#3D9BA8);border-top-color:transparent;animation:ev2-steps-spin .8s linear infinite}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-steps-css')){const s=document.createElement('style');s.id='ev2-steps-css';s.textContent=ev2StepsCss;document.head.appendChild(s);}})();

export function Steps({ steps = [] }) {
  const marker = (status) => {
    if (status === 'success') return <svg viewBox="0 0 24 24" fill="none" stroke="var(--enc-void,#0A0A0F)" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 12 10 18 20 6"/></svg>;
    if (status === 'error') return <svg viewBox="0 0 24 24" fill="none" stroke="var(--enc-starlight,#EEF2F7)" strokeWidth="3" strokeLinecap="round"><line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/></svg>;
    if (status === 'loading') return <span className="ev2-step__spin"></span>;
    return null;
  };
  return (
    <div className="ev2-steps">
      {steps.map((s, i) => (
        <div className={`ev2-step ev2-step--${s.status || 'pending'}`} key={i}>
          <div className="ev2-step__rail">
            <span className="ev2-step__marker" aria-hidden="true">{marker(s.status)}</span>
            <span className="ev2-step__line"></span>
          </div>
          <div className="ev2-step__content">
            <div className="ev2-step__header">{s.header}</div>
            {s.details && <div className="ev2-step__detail">{s.details}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}
