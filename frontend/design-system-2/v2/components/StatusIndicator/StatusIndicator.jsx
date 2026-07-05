// Enceladus v2 · StatusIndicator — Cloudscape StatusIndicator, deep re-brand.
const ev2StatusCss = `
.ev2-status{display:inline-flex;align-items:center;gap:7px;font-family:var(--font-mono,monospace);font-size:12.5px;font-weight:500;line-height:1}
.ev2-status__dot{width:8px;height:8px;border-radius:50%;background:currentColor;flex:0 0 auto}
.ev2-status--in-progress .ev2-status__dot,.ev2-status--loading .ev2-status__dot{animation:ev2-status-pulse 1.6s var(--ease-orbit,cubic-bezier(.4,0,.2,1)) infinite}
@keyframes ev2-status-pulse{0%,100%{opacity:1}50%{opacity:.3}}
@media (prefers-reduced-motion: reduce){.ev2-status__dot{animation:none !important}}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-status-css')){const s=document.createElement('style');s.id='ev2-status-css';s.textContent=ev2StatusCss;document.head.appendChild(s);}})();

const EV2_STATUS_COLORS = {
  'success':     'var(--v2-status-success,#3D9BA8)',
  'error':       'var(--v2-status-error,#C85060)',
  'warning':     'var(--v2-status-warning,#C9A15C)',
  'info':        'var(--v2-status-info,#7AC8D4)',
  'pending':     'var(--v2-status-pending,#8A8CB5)',
  'in-progress': 'var(--v2-status-info,#7AC8D4)',
  'loading':     'var(--v2-status-info,#7AC8D4)',
  'stopped':     'var(--v2-status-stopped,#6B8A94)',
};

export function StatusIndicator({ type = 'success', children }) {
  return (
    <span className={`ev2-status ev2-status--${type}`} style={{ color: EV2_STATUS_COLORS[type] || EV2_STATUS_COLORS.success }}>
      <span className="ev2-status__dot" aria-hidden="true"></span>
      {children}
    </span>
  );
}
