// Enceladus v2 · Badge — Cloudscape Badge, deep re-brand.
const ev2BadgeCss = `
.ev2-badge{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:var(--v2-chip-radius,4px);font-family:var(--font-mono,monospace);font-size:12px;font-weight:500;line-height:18px;border:1px solid transparent;white-space:nowrap}
.ev2-badge--teal{background:rgba(61,155,168,.1);color:#3D9BA8;border-color:rgba(61,155,168,.5)}
.ev2-badge--teal-light{background:rgba(122,200,212,.12);color:#7AC8D4;border-color:rgba(122,200,212,.45)}
.ev2-badge--crimson{background:rgba(200,80,96,.1);color:#C85060;border-color:rgba(200,80,96,.5)}
.ev2-badge--lavender{background:rgba(138,140,181,.12);color:#8A8CB5;border-color:rgba(138,140,181,.45)}
.ev2-badge--dust{background:rgba(107,138,148,.1);color:#6B8A94;border-color:rgba(107,138,148,.4)}
.ev2-badge--amber{background:rgba(201,161,92,.1);color:#C9A15C;border-color:rgba(201,161,92,.45)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-badge-css')){const s=document.createElement('style');s.id='ev2-badge-css';s.textContent=ev2BadgeCss;document.head.appendChild(s);}})();

export function Badge({ color = 'teal', children }) {
  return <span className={`ev2-badge ev2-badge--${color}`}>{children}</span>;
}
