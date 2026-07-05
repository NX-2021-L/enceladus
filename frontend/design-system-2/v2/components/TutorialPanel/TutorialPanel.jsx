// Enceladus v2 · TutorialPanel — Cloudscape TutorialPanel, deep re-brand.
const ev2TutCss = `
.ev2-tut{font-family:var(--font-body,'Inter',sans-serif);background:var(--enc-surface,#111827);border-left:1px solid var(--v2-divider,rgba(61,155,168,.12));padding:20px 22px;min-width:300px;box-sizing:border-box;height:100%;overflow-y:auto}
.ev2-tut__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:16px;color:var(--enc-seafoam,#C8DDD9);margin:0 0 4px}
.ev2-tut__sub{font-size:12.5px;color:var(--enc-dust,#6B8A94);margin:0 0 16px}
.ev2-tut__tut{border:1px solid var(--v2-panel-border,rgba(61,155,168,.2));border-radius:var(--v2-panel-radius,8px);padding:14px 16px;margin-bottom:10px;transition:border-color var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-tut__tut:hover{border-color:rgba(61,155,168,.42)}
.ev2-tut__tut-head{display:flex;align-items:baseline;justify-content:space-between;gap:10px;margin-bottom:5px}
.ev2-tut__tut-title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;color:var(--enc-seafoam,#C8DDD9)}
.ev2-tut__tut-meta{font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-dust,#6B8A94)}
.ev2-tut__tut-desc{font-size:12.5px;line-height:1.55;color:var(--enc-starlight,#EEF2F7);margin-bottom:10px}
.ev2-tut__prog{height:4px;background:var(--enc-slate,#2E4D5C);border-radius:2px;overflow:hidden;margin-bottom:10px}
.ev2-tut__prog-fill{height:100%;background:var(--enc-teal,#3D9BA8);border-radius:2px;transition:width var(--dur-slow,300ms) var(--ease-orbit)}
.ev2-tut__start{appearance:none;border:1px solid var(--enc-teal,#3D9BA8);background:none;color:var(--enc-teal,#3D9BA8);border-radius:6px;padding:6px 14px;font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:13px;cursor:pointer;transition:all var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-tut__start:hover{background:rgba(61,155,168,.08);color:var(--enc-teal-light,#7AC8D4)}
.ev2-tut__done{font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-teal,#3D9BA8)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-tut-css')){const s=document.createElement('style');s.id='ev2-tut-css';s.textContent=ev2TutCss;document.head.appendChild(s);}})();

export function TutorialPanel({ title = 'Tutorials', subtitle, tutorials = [], onStart }) {
  return (
    <aside className="ev2-tut" aria-label="Tutorial panel">
      <h2 className="ev2-tut__title">{title}</h2>
      {subtitle && <p className="ev2-tut__sub">{subtitle}</p>}
      {tutorials.map((t, i) => {
        const total = t.stepsCount || 0;
        const done = t.completedSteps || 0;
        const pct = total ? Math.round((done / total) * 100) : 0;
        const complete = total > 0 && done >= total;
        return (
          <div className="ev2-tut__tut" key={i}>
            <div className="ev2-tut__tut-head">
              <span className="ev2-tut__tut-title">{t.title}</span>
              {total > 0 && <span className="ev2-tut__tut-meta">{done}/{total}</span>}
            </div>
            {t.description && <div className="ev2-tut__tut-desc">{t.description}</div>}
            {total > 0 && <div className="ev2-tut__prog"><div className="ev2-tut__prog-fill" style={{ width: `${pct}%` }}></div></div>}
            {complete
              ? <span className="ev2-tut__done">✓ Completed</span>
              : <button className="ev2-tut__start" onClick={() => onStart && onStart({ detail: { index: i } })}>{done > 0 ? 'Continue' : 'Start'}</button>}
          </div>
        );
      })}
    </aside>
  );
}
