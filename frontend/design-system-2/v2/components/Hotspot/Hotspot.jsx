// Enceladus v2 · Hotspot — Cloudscape Hotspot (annotation anchor), deep re-brand.
const ev2HotCss = `
.ev2-hot{position:relative;display:inline-flex;vertical-align:middle}
.ev2-hot__dot{width:16px;height:16px;border-radius:50%;background:var(--enc-teal,#3D9BA8);cursor:pointer;position:relative;flex:0 0 auto;border:none;padding:0}
.ev2-hot__dot::before{content:'';position:absolute;inset:-4px;border-radius:50%;background:rgba(61,155,168,.4);animation:ev2-hot-pulse 1.8s var(--ease-orbit,cubic-bezier(.4,0,.2,1)) infinite;z-index:-1}
@keyframes ev2-hot-pulse{0%{transform:scale(.8);opacity:.7}70%{transform:scale(1.6);opacity:0}100%{opacity:0}}
@media (prefers-reduced-motion: reduce){.ev2-hot__dot::before{animation:none}}
.ev2-hot__dot::after{content:'i';position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-family:var(--font-mono,monospace);font-size:10px;font-weight:600;color:var(--enc-void,#0A0A0F)}
.ev2-hot__pop{position:absolute;z-index:40;bottom:calc(100% + 10px);left:50%;transform:translateX(-50%);width:240px;background:var(--enc-surface,#111827);border:1px solid var(--enc-teal,#3D9BA8);border-radius:var(--v2-panel-radius,8px);box-shadow:var(--v2-dropdown-shadow,0 8px 32px rgba(0,0,0,.6));padding:12px 14px}
.ev2-hot__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:13px;color:var(--enc-seafoam,#C8DDD9);margin:0 0 4px}
.ev2-hot__text{font-size:12.5px;line-height:1.5;color:var(--enc-starlight,#EEF2F7)}
.ev2-hot__step{font-family:var(--font-mono,monospace);font-size:10px;color:var(--enc-dust,#6B8A94);margin-top:8px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-hot-css')){const s=document.createElement('style');s.id='ev2-hot-css';s.textContent=ev2HotCss;document.head.appendChild(s);}})();

export function Hotspot({ title, content, stepText, side = 'top', defaultOpen = false }) {
  const [open, setOpen] = React.useState(defaultOpen);
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!open) return;
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);
  return (
    <span className="ev2-hot" ref={ref}>
      <button className="ev2-hot__dot" aria-label={title || 'Annotation'} onClick={() => setOpen((o) => !o)}></button>
      {open && (
        <span className="ev2-hot__pop" role="dialog">
          {title && <span className="ev2-hot__title" style={{ display: 'block' }}>{title}</span>}
          <span className="ev2-hot__text" style={{ display: 'block' }}>{content}</span>
          {stepText && <span className="ev2-hot__step" style={{ display: 'block' }}>{stepText}</span>}
        </span>
      )}
    </span>
  );
}
