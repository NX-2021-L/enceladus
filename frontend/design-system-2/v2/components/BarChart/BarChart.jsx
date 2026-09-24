// Enceladus v2 · BarChart — inline SVG, teal-family palette, mono axes.
const ev2BarChartCss = `
.ev2-barc{font-family:var(--font-body,'Inter',sans-serif)}
.ev2-barc__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;color:var(--enc-seafoam,#C8DDD9);margin:0 0 2px}
.ev2-barc__sub{font-size:12px;color:var(--enc-dust,#6B8A94);margin:0 0 12px}
.ev2-barc__axis{font-family:var(--font-mono,monospace);font-size:10px;fill:var(--enc-dust,#6B8A94)}
.ev2-barc__grid{stroke:rgba(61,155,168,.1)}
.ev2-barc__bar{transform-origin:bottom;animation:ev2-barc-grow .5s var(--ease-orbit,cubic-bezier(.4,0,.2,1)) both}
@keyframes ev2-barc-grow{from{transform:scaleY(0)}to{transform:scaleY(1)}}
@media (prefers-reduced-motion: reduce){.ev2-barc__bar{animation:none}}
.ev2-barc__legend{display:flex;flex-wrap:wrap;gap:12px;margin-top:12px}
.ev2-barc__leg{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--enc-starlight,#EEF2F7)}
.ev2-barc__sw{width:10px;height:10px;border-radius:2px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-barc-css')){const s=document.createElement('style');s.id='ev2-barc-css';s.textContent=ev2BarChartCss;document.head.appendChild(s);}})();

const EV2_BAR_PALETTE = ['#3D9BA8', '#7AC8D4', '#8A8CB5', '#C85060', '#C9A15C'];
function ev2NiceMax(v){ if(v<=0)return 1; const p=Math.pow(10,Math.floor(Math.log10(v))); const n=v/p; const s=n<=1?1:n<=2?2:n<=5?5:10; return s*p; }

export function BarChart({ series = [], xDomain = [], title, subtitle, height = 220, horizontal = false, stacked = false }) {
  const W = 460, H = height, padL = 40, padB = 28, padT = 8, padR = 8;
  const iw = W - padL - padR, ih = H - padT - padB;
  const groups = xDomain.length;
  const rawMax = stacked
    ? Math.max(...xDomain.map((_, gi) => series.reduce((sum, s) => sum + (s.data[gi] || 0), 0)), 1)
    : Math.max(...series.flatMap((s) => s.data), 1);
  const max = ev2NiceMax(rawMax);
  const ticks = 4;
  const groupW = iw / groups;
  const barW = stacked ? groupW * 0.5 : (groupW * 0.7) / series.length;
  return (
    <div className="ev2-barc">
      {title && <div className="ev2-barc__title">{title}</div>}
      {subtitle && <div className="ev2-barc__sub">{subtitle}</div>}
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={title || 'Bar chart'}>
        {Array.from({ length: ticks + 1 }).map((_, i) => {
          const y = padT + (ih / ticks) * i;
          const val = Math.round(max - (max / ticks) * i);
          return (
            <g key={i}>
              <line className="ev2-barc__grid" x1={padL} y1={y} x2={W - padR} y2={y} />
              <text className="ev2-barc__axis" x={padL - 6} y={y + 3} textAnchor="end">{val}</text>
            </g>
          );
        })}
        {xDomain.map((label, gi) => {
          let stackY = padT + ih;
          return (
            <g key={gi}>
              {series.map((s, si) => {
                const v = s.data[gi] || 0;
                const bh = (v / max) * ih;
                let x, y;
                if (stacked) { x = padL + gi * groupW + (groupW - barW) / 2; stackY -= bh; y = stackY; }
                else { x = padL + gi * groupW + (groupW * 0.15) + si * barW; y = padT + ih - bh; }
                return <rect key={si} className="ev2-barc__bar" x={x} y={y} width={barW - (stacked ? 0 : 2)} height={Math.max(bh, 0)}
                  rx="2" fill={s.color || EV2_BAR_PALETTE[si % EV2_BAR_PALETTE.length]} style={{ animationDelay: `${gi * 60 + si * 30}ms` }} />;
              })}
              <text className="ev2-barc__axis" x={padL + gi * groupW + groupW / 2} y={H - padB + 14} textAnchor="middle">{label}</text>
            </g>
          );
        })}
      </svg>
      {series.length > 1 && (
        <div className="ev2-barc__legend">
          {series.map((s, i) => (
            <span className="ev2-barc__leg" key={i}><span className="ev2-barc__sw" style={{ background: s.color || EV2_BAR_PALETTE[i % EV2_BAR_PALETTE.length] }}></span>{s.title}</span>
          ))}
        </div>
      )}
    </div>
  );
}
