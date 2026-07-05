// Enceladus v2 · MixedChart — inline SVG: bars + overlaid line. Teal-family, mono axes.
const ev2MixCss = `
.ev2-mixc{font-family:var(--font-body,'Inter',sans-serif)}
.ev2-mixc__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;color:var(--enc-seafoam,#C8DDD9);margin:0 0 2px}
.ev2-mixc__sub{font-size:12px;color:var(--enc-dust,#6B8A94);margin:0 0 12px}
.ev2-mixc__axis{font-family:var(--font-mono,monospace);font-size:10px;fill:var(--enc-dust,#6B8A94)}
.ev2-mixc__grid{stroke:rgba(61,155,168,.1)}
.ev2-mixc__bar{transform-origin:bottom;animation:ev2-mixc-grow .5s var(--ease-orbit,cubic-bezier(.4,0,.2,1)) both}
.ev2-mixc__line{fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:1400;stroke-dashoffset:1400;animation:ev2-mixc-draw 1s var(--ease-orbit) .3s forwards}
@keyframes ev2-mixc-grow{from{transform:scaleY(0)}to{transform:scaleY(1)}}
@keyframes ev2-mixc-draw{to{stroke-dashoffset:0}}
@media (prefers-reduced-motion: reduce){.ev2-mixc__bar,.ev2-mixc__line{animation:none;stroke-dashoffset:0}}
.ev2-mixc__legend{display:flex;flex-wrap:wrap;gap:12px;margin-top:12px}
.ev2-mixc__leg{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--enc-starlight,#EEF2F7)}
.ev2-mixc__sw{width:10px;height:10px;border-radius:2px}
.ev2-mixc__sw--line{height:2px;border-radius:1px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-mixc-css')){const s=document.createElement('style');s.id='ev2-mixc-css';s.textContent=ev2MixCss;document.head.appendChild(s);}})();

function ev2NiceMax(v){ if(v<=0)return 1; const p=Math.pow(10,Math.floor(Math.log10(v))); const n=v/p; const s=n<=1?1:n<=2?2:n<=5?5:10; return s*p; }

export function MixedChart({ bars, line, xDomain = [], title, subtitle, height = 220, barColor = '#3D9BA8', lineColor = '#C9A15C' }) {
  const W = 460, H = height, padL = 40, padB = 28, padT = 8, padR = 10;
  const iw = W - padL - padR, ih = H - padT - padB;
  const n = xDomain.length;
  const max = ev2NiceMax(Math.max(...(bars ? bars.data : [0]), ...(line ? line.data : [0]), 1));
  const ticks = 4;
  const groupW = iw / n, barW = groupW * 0.5;
  const xCenter = (i) => padL + groupW * i + groupW / 2;
  const yAt = (v) => padT + ih - (v / max) * ih;
  return (
    <div className="ev2-mixc">
      {title && <div className="ev2-mixc__title">{title}</div>}
      {subtitle && <div className="ev2-mixc__sub">{subtitle}</div>}
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={title || 'Mixed chart'}>
        {Array.from({ length: ticks + 1 }).map((_, i) => {
          const y = padT + (ih / ticks) * i;
          return (
            <g key={i}>
              <line className="ev2-mixc__grid" x1={padL} y1={y} x2={W - padR} y2={y} />
              <text className="ev2-mixc__axis" x={padL - 6} y={y + 3} textAnchor="end">{Math.round(max - (max / ticks) * i)}</text>
            </g>
          );
        })}
        {xDomain.map((label, i) => <text key={i} className="ev2-mixc__axis" x={xCenter(i)} y={H - padB + 14} textAnchor="middle">{label}</text>)}
        {bars && xDomain.map((_, i) => {
          const bh = (bars.data[i] / max) * ih;
          return <rect key={i} className="ev2-mixc__bar" x={xCenter(i) - barW / 2} y={padT + ih - bh} width={barW} height={Math.max(bh, 0)} rx="2" fill={bars.color || barColor} style={{ animationDelay: `${i * 55}ms` }} />;
        })}
        {line && <path className="ev2-mixc__line" d={line.data.map((v, i) => `${i === 0 ? 'M' : 'L'} ${xCenter(i)} ${yAt(v)}`).join(' ')} stroke={line.color || lineColor} />}
        {line && line.data.map((v, i) => <circle key={i} cx={xCenter(i)} cy={yAt(v)} r="3" fill={line.color || lineColor} style={{ opacity: 0, animation: 'ev2-chart-fade .3s ease forwards', animationDelay: `${1000 + i * 30}ms` }} />)}
      </svg>
      <div className="ev2-mixc__legend">
        {bars && <span className="ev2-mixc__leg"><span className="ev2-mixc__sw" style={{ background: bars.color || barColor }}></span>{bars.title}</span>}
        {line && <span className="ev2-mixc__leg"><span className="ev2-mixc__sw ev2-mixc__sw--line" style={{ background: line.color || lineColor, width: 14 }}></span>{line.title}</span>}
      </div>
    </div>
  );
}
