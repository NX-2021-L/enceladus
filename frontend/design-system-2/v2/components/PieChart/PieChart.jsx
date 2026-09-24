// Enceladus v2 · PieChart — inline SVG donut, teal-family palette, mono center.
const ev2PieCss = `
.ev2-piec{font-family:var(--font-body,'Inter',sans-serif);display:flex;align-items:center;gap:22px;flex-wrap:wrap}
.ev2-piec__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;color:var(--enc-seafoam,#C8DDD9);margin:0 0 2px}
.ev2-piec__sub{font-size:12px;color:var(--enc-dust,#6B8A94);margin:0 0 12px}
.ev2-piec__seg{transform-origin:center;animation:ev2-piec-fade .6s var(--ease-orbit,cubic-bezier(.4,0,.2,1)) both}
@keyframes ev2-piec-fade{from{opacity:0}to{opacity:1}}
@media (prefers-reduced-motion: reduce){.ev2-piec__seg{animation:none}}
.ev2-piec__center-v{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:22px;fill:var(--enc-seafoam,#C8DDD9)}
.ev2-piec__center-l{font-family:var(--font-mono,monospace);font-size:9px;fill:var(--enc-dust,#6B8A94)}
.ev2-piec__legend{display:flex;flex-direction:column;gap:7px}
.ev2-piec__leg{display:inline-flex;align-items:center;gap:8px;font-size:12.5px;color:var(--enc-starlight,#EEF2F7)}
.ev2-piec__sw{width:10px;height:10px;border-radius:2px;flex:0 0 auto}
.ev2-piec__val{font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-dust,#6B8A94);margin-left:auto}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-piec-css')){const s=document.createElement('style');s.id='ev2-piec-css';s.textContent=ev2PieCss;document.head.appendChild(s);}})();

const EV2_PIE_PALETTE = ['#3D9BA8', '#7AC8D4', '#8A8CB5', '#C9A15C', '#C85060', '#6B8A94'];

export function PieChart({ data = [], title, subtitle, variant = 'donut', size = 150, centerLabel }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  const R = size / 2, cx = R, cy = R, stroke = variant === 'donut' ? size * 0.22 : R;
  const rr = variant === 'donut' ? R - stroke / 2 : R;
  let acc = 0;
  const circ = 2 * Math.PI * rr;
  return (
    <div className="ev2-piec">
      <div>
        {title && <div className="ev2-piec__title">{title}</div>}
        {subtitle && <div className="ev2-piec__sub">{subtitle}</div>}
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={title || 'Pie chart'}>
          <g transform={`rotate(-90 ${cx} ${cy})`}>
            {data.map((d, i) => {
              const frac = d.value / total;
              const dash = frac * circ;
              const seg = (
                <circle key={i} className="ev2-piec__seg" cx={cx} cy={cy} r={rr} fill="none"
                  stroke={d.color || EV2_PIE_PALETTE[i % EV2_PIE_PALETTE.length]} strokeWidth={stroke}
                  strokeDasharray={`${dash} ${circ - dash}`} strokeDashoffset={-acc * circ}
                  style={{ animationDelay: `${i * 80}ms` }} />
              );
              acc += frac;
              return seg;
            })}
          </g>
          {variant === 'donut' && (
            <g>
              <text className="ev2-piec__center-v" x={cx} y={cy} textAnchor="middle" dominantBaseline="central">{centerLabel != null ? centerLabel : total}</text>
              <text className="ev2-piec__center-l" x={cx} y={cy + 16} textAnchor="middle">{centerLabel != null ? '' : 'TOTAL'}</text>
            </g>
          )}
        </svg>
      </div>
      <div className="ev2-piec__legend">
        {data.map((d, i) => (
          <span className="ev2-piec__leg" key={i}>
            <span className="ev2-piec__sw" style={{ background: d.color || EV2_PIE_PALETTE[i % EV2_PIE_PALETTE.length] }}></span>
            {d.title}
            <span className="ev2-piec__val">{Math.round((d.value / total) * 100)}%</span>
          </span>
        ))}
      </div>
    </div>
  );
}
