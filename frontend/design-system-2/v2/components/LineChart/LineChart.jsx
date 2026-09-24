// Enceladus v2 · LineChart — inline SVG, teal draw-in, mono axes.
const ev2LineCss = `
.ev2-linec{font-family:var(--font-body,'Inter',sans-serif)}
.ev2-linec__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;color:var(--enc-seafoam,#C8DDD9);margin:0 0 2px}
.ev2-linec__sub{font-size:12px;color:var(--enc-dust,#6B8A94);margin:0 0 12px}
.ev2-linec__axis{font-family:var(--font-mono,monospace);font-size:10px;fill:var(--enc-dust,#6B8A94)}
.ev2-linec__grid{stroke:rgba(61,155,168,.1)}
.ev2-linec__path{fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:1400;stroke-dashoffset:1400;animation:ev2-linec-draw 1s var(--ease-orbit,cubic-bezier(.4,0,.2,1)) forwards}
@keyframes ev2-linec-draw{to{stroke-dashoffset:0}}
.ev2-linec__dot{animation:ev2-linec-fade .4s var(--ease-orbit) both}
@keyframes ev2-linec-fade{from{opacity:0}to{opacity:1}}
@media (prefers-reduced-motion: reduce){.ev2-linec__path{animation:none;stroke-dashoffset:0}.ev2-linec__dot{animation:none}}
.ev2-linec__legend{display:flex;flex-wrap:wrap;gap:12px;margin-top:12px}
.ev2-linec__leg{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--enc-starlight,#EEF2F7)}
.ev2-linec__sw{width:12px;height:2px;border-radius:1px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-linec-css')){const s=document.createElement('style');s.id='ev2-linec-css';s.textContent=ev2LineCss;document.head.appendChild(s);}})();

const EV2_LINE_PALETTE = ['#3D9BA8', '#8A8CB5', '#C9A15C', '#C85060'];
function ev2NiceMax(v){ if(v<=0)return 1; const p=Math.pow(10,Math.floor(Math.log10(v))); const n=v/p; const s=n<=1?1:n<=2?2:n<=5?5:10; return s*p; }

export function LineChart({ series = [], xDomain = [], title, subtitle, height = 220, yMax }) {
  const W = 460, H = height, padL = 40, padB = 28, padT = 8, padR = 10;
  const iw = W - padL - padR, ih = H - padT - padB;
  const n = xDomain.length;
  const max = yMax || ev2NiceMax(Math.max(...series.flatMap((s) => s.data), 1));
  const ticks = 4;
  const xAt = (i) => padL + (n <= 1 ? iw / 2 : (iw / (n - 1)) * i);
  const yAt = (v) => padT + ih - (v / max) * ih;
  return (
    <div className="ev2-linec">
      {title && <div className="ev2-linec__title">{title}</div>}
      {subtitle && <div className="ev2-linec__sub">{subtitle}</div>}
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={title || 'Line chart'}>
        {Array.from({ length: ticks + 1 }).map((_, i) => {
          const y = padT + (ih / ticks) * i;
          const val = (max - (max / ticks) * i);
          return (
            <g key={i}>
              <line className="ev2-linec__grid" x1={padL} y1={y} x2={W - padR} y2={y} />
              <text className="ev2-linec__axis" x={padL - 6} y={y + 3} textAnchor="end">{Number.isInteger(max) ? Math.round(val) : val.toFixed(1)}</text>
            </g>
          );
        })}
        {xDomain.map((label, i) => <text key={i} className="ev2-linec__axis" x={xAt(i)} y={H - padB + 14} textAnchor="middle">{label}</text>)}
        {series.map((s, si) => {
          const color = s.color || EV2_LINE_PALETTE[si % EV2_LINE_PALETTE.length];
          const d = s.data.map((v, i) => `${i === 0 ? 'M' : 'L'} ${xAt(i)} ${yAt(v)}`).join(' ');
          return (
            <g key={si}>
              <path className="ev2-linec__path" d={d} stroke={color} style={{ animationDelay: `${si * 120}ms` }} />
              {s.data.map((v, i) => <circle key={i} className="ev2-linec__dot" cx={xAt(i)} cy={yAt(v)} r="3" fill={color} style={{ animationDelay: `${600 + i * 40}ms` }} />)}
            </g>
          );
        })}
      </svg>
      {series.length > 1 && (
        <div className="ev2-linec__legend">
          {series.map((s, i) => <span className="ev2-linec__leg" key={i}><span className="ev2-linec__sw" style={{ background: s.color || EV2_LINE_PALETTE[i % EV2_LINE_PALETTE.length] }}></span>{s.title}</span>)}
        </div>
      )}
    </div>
  );
}
