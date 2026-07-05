// Enceladus v2 · ProgressBar — Cloudscape ProgressBar, deep re-brand.
const ev2ProgressCss = `
.ev2-progress{font-family:var(--font-body,'Inter',sans-serif)}
.ev2-progress__label{font-size:13px;font-weight:500;color:var(--enc-starlight,#EEF2F7);margin-bottom:2px;display:flex;justify-content:space-between;align-items:baseline;gap:12px}
.ev2-progress__value{font-family:var(--font-mono,monospace);font-size:12px;color:var(--enc-teal,#3D9BA8);font-variant-numeric:tabular-nums}
.ev2-progress__desc{font-size:12px;color:var(--enc-dust,#6B8A94);margin-bottom:6px}
.ev2-progress__track{height:6px;background:var(--enc-slate,#2E4D5C);border-radius:3px;overflow:hidden}
.ev2-progress__fill{height:100%;border-radius:3px;background:var(--enc-teal,#3D9BA8);transition:width var(--dur-slow,300ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-progress--error .ev2-progress__fill{background:var(--enc-crimson,#C85060)}
.ev2-progress--error .ev2-progress__value{color:var(--enc-crimson,#C85060)}
.ev2-progress__result{margin-top:6px;font-family:var(--font-mono,monospace);font-size:12.5px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-progress-css')){const s=document.createElement('style');s.id='ev2-progress-css';s.textContent=ev2ProgressCss;document.head.appendChild(s);}})();

export function ProgressBar({ value = 0, label, description, status, resultText }) {
  const clamped = Math.max(0, Math.min(100, value));
  const isError = status === 'error';
  return (
    <div className={`ev2-progress${isError ? ' ev2-progress--error' : ''}`}>
      {(label || true) && (
        <div className="ev2-progress__label">
          <span>{label}</span>
          <span className="ev2-progress__value">{clamped}%</span>
        </div>
      )}
      {description && <div className="ev2-progress__desc">{description}</div>}
      <div className="ev2-progress__track" role="progressbar" aria-valuenow={clamped} aria-valuemin="0" aria-valuemax="100">
        <div className="ev2-progress__fill" style={{ width: `${clamped}%` }}></div>
      </div>
      {resultText && (
        <div className="ev2-progress__result" style={{ color: isError ? 'var(--enc-crimson,#C85060)' : 'var(--enc-teal,#3D9BA8)' }}>
          {resultText}
        </div>
      )}
    </div>
  );
}
