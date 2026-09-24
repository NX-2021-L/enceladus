// Enceladus v2 · ButtonGroup — Cloudscape ButtonGroup, deep re-brand (icon action strip).
const ev2BgCss = `
.ev2-bg{display:inline-flex;align-items:center;padding:2px;background:var(--v2-field-bg,#0D1220);border:1px solid var(--v2-field-border,rgba(61,155,168,.25));border-radius:var(--v2-control-radius,6px);gap:1px}
.ev2-bg__btn{appearance:none;border:none;background:none;width:30px;height:28px;border-radius:4px;color:var(--enc-dust,#6B8A94);cursor:pointer;display:inline-flex;align-items:center;justify-content:center;transition:all var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-bg__btn:hover:not(:disabled){color:var(--enc-teal-light,#7AC8D4);background:rgba(61,155,168,.1)}
.ev2-bg__btn:disabled{opacity:.35;cursor:not-allowed}
.ev2-bg__btn svg{width:16px;height:16px}
.ev2-bg__sep{width:1px;height:16px;background:var(--v2-divider,rgba(61,155,168,.15));margin:0 2px}
.ev2-bg__feedback{position:relative}
.ev2-bg__tip{position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:var(--enc-teal,#3D9BA8);color:var(--enc-void,#0A0A0F);font-family:var(--font-mono,monospace);font-size:10px;padding:2px 7px;border-radius:3px;white-space:nowrap;animation:ev2-bg-tip var(--dur-base,200ms) var(--ease-orbit)}
@keyframes ev2-bg-tip{from{opacity:0;transform:translateX(-50%) translateY(3px)}to{opacity:1;transform:translateX(-50%)}}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-bg-css')){const s=document.createElement('style');s.id='ev2-bg-css';s.textContent=ev2BgCss;document.head.appendChild(s);}})();

export function ButtonGroup({ items = [], onItemClick }) {
  const [feedback, setFeedback] = React.useState(null);
  const click = (it) => {
    if (it.disabled) return;
    onItemClick && onItemClick({ detail: { id: it.id } });
    if (it.popoverFeedback) { setFeedback(it.id); setTimeout(() => setFeedback(null), 1200); }
  };
  return (
    <div className="ev2-bg" role="group">
      {items.map((it, i) => it.type === 'separator'
        ? <span className="ev2-bg__sep" key={i} aria-hidden="true"></span>
        : (
          <span className="ev2-bg__feedback" key={it.id || i}>
            <button className="ev2-bg__btn" disabled={it.disabled} aria-label={it.text} title={it.text} onClick={() => click(it)}>{it.icon}</button>
            {feedback === it.id && <span className="ev2-bg__tip">{it.popoverFeedback}</span>}
          </span>
        ))}
    </div>
  );
}
