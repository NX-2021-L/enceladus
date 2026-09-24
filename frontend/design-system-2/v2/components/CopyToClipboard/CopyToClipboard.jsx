// Enceladus v2 · CopyToClipboard — Cloudscape CopyToClipboard, deep re-brand.
const ev2CopyCss = `
.ev2-copy{display:inline-flex;align-items:center;gap:8px;font-family:var(--font-mono,monospace)}
.ev2-copy__text{font-size:13px;color:var(--enc-teal,#3D9BA8)}
.ev2-copy__btn{appearance:none;border:1px solid var(--v2-field-border,rgba(61,155,168,.3));background:var(--v2-field-bg,#0D1220);width:26px;height:26px;border-radius:5px;color:var(--enc-dust,#6B8A94);cursor:pointer;display:inline-flex;align-items:center;justify-content:center;transition:all var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-copy__btn:hover{color:var(--enc-teal-light,#7AC8D4);border-color:rgba(61,155,168,.5)}
.ev2-copy__btn--done{color:var(--enc-teal,#3D9BA8);border-color:var(--enc-teal,#3D9BA8)}
.ev2-copy__btn svg{width:14px;height:14px}
.ev2-copy__label{font-family:var(--font-body,sans-serif);font-size:11px;color:var(--enc-teal,#3D9BA8)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-copy-css')){const s=document.createElement('style');s.id='ev2-copy-css';s.textContent=ev2CopyCss;document.head.appendChild(s);}})();

export function CopyToClipboard({ textToCopy = '', displayText, variant = 'inline' }) {
  const [done, setDone] = React.useState(false);
  const copy = () => {
    try { navigator.clipboard && navigator.clipboard.writeText(textToCopy); } catch (e) { /* no-op */ }
    setDone(true); setTimeout(() => setDone(false), 1400);
  };
  const icon = done
    ? <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 12 10 18 20 6"/></svg>
    : <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>;
  return (
    <span className="ev2-copy">
      {variant === 'inline' && <span className="ev2-copy__text">{displayText || textToCopy}</span>}
      <button className={`ev2-copy__btn${done ? ' ev2-copy__btn--done' : ''}`} aria-label={done ? 'Copied' : 'Copy'} onClick={copy}>{icon}</button>
      {variant === 'button' && <span className="ev2-copy__label">{done ? 'Copied' : (displayText || 'Copy')}</span>}
    </span>
  );
}
