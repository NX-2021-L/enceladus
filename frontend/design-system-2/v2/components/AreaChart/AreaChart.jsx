// Enceladus v2 · AreaChart — inline SVG, teal gradient fill, mono axes.
const ev2AreaCss = `
.ev2-areac{font-family:var(--font-body,'Inter',sans-serif)}
.ev2-areac__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;color:var(--enc-seafoam,#C8DDD9);margin:0 0 2px}
.ev2-areac__sub{font-size:12px;color:var(--enc-dust,#6B8A94);margin:0 0 12px}
.ev2-areac__axis{font-family:var(--font-mono,monospace);font-size:10px;fill:var(--enc-dust,#6B8A94)}
.ev2-areac__grid{stroke:rgba(61,155,168,.1)}
.ev2-areac__area{animation:ev2-areac-fade .7s var(--ease-orbit,cubic-bezier(.4,0,.2,1)) both}
.ev2-areac__line{fill:none;stroke-width:2}
@keyframes ev2-areac-fade{from{opacity:0}to{opacity:1}}
@media (prefers-reduced-motion: reduce){.ev2-areac__area{animation:none}}
.ev2-areac__legend{display:flex;flex-wrap:wrap;gap:12px;margin-top:12px}
.ev2-areac__leg{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--enc-starlight,#EEF2F7)}
.ev2-areac__sw{width:10px;height:10px;border-radius:2px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-areac-css')){const s=document.createElement('style');s.id='ev2-areac-css';s.textContent=ev2AreaCss;document.head.appendChild(s);}})();

const EV2_AREA_PALETTE = ['#3D9BA8', '#8A8CB5', '#C9A15C'];
function ev2NiceMax(v){ if(v<=0)return 1; const p=Math.pow(10,Math.floor(Math.log10(v))); const n=v/p; const s=n<=1?1:n<=2?2:n<=5?5:10; return s*p; }

export function AreaChart({ series = [], xDomain = [], title, subtitle, height = 220, stacked = true }) {
  const W = 460, H = height, padL = 40, padB = 28, padT = 8, padR = 10;
  const iw = W - padL - padR, ih = H - padT - padB;
  const n = xDomain.length;
  const uid = React.useId().replace(/:/g, '');
  const stackTotals = xDomain.map((_, i) => series.reduce((sum, s) => sum + (s.data[i] || 0), 0));
  const max = ev2NiceMax(stacked ? Math.max(...stackTotals, 1) : Math.max(...series.flatMap((s) => s.data), 1));
  const ticks = 4;
  const xAt = (i) => padL + (n <= 1 ? iw / 2 : (iw / (n - 1)) * i);
  const yAt = (v) => padT + ih - (v / max) * ih;
  const baseline = new Array(n).fill(0);
  return (
    <div className="ev2-areac">
      {title && <div className="ev2-areac__title">{title}</div>}
      {subtitle && <div className="ev2-areac__sub">{subtitle}</div>}
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={title || 'Area chart'}>
        <defs>
          {series.map((s, si) => {
            const color = s.color || EV2_AREA_PALETTE[si % EV2_AREA_PALETTE.length];
            return (
              <linearGradient key={si} id={`${uid}-g${si}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={color} stopOpacity="0.45" />
                <stop offset="100%" stopColor={color} stopOpacity="0.04" />
              </linearGradient>
            );
          })}
        </defs>
        {Array.from({ length: ticks + 1 }).map((_, i) => {
          const y = padT + (ih / ticks) * i;
          return (
            <g key={i}>
              <line className="ev2-areac__grid" x1={padL} y1={y} x2={W - padR} y2={y} />
              <text className="ev2-areac__axis" x={padL - 6} y={y + 3} textAnchor="end">{Math.round(max - (max / ticks) * i)}</text>
            </g>
          );
        })}
        {xDomain.map((label, i) => <text key={i} className="ev2-areac__axis" x={xAt(i)} y={H - padB + 14} textAnchor="middle">{label}</text>)}
        {series.map((s, si) => {
          const color = s.color || EV2_AREA_PALETTE[si % EV2_AREA_PALETTE.length];
          const tops = s.data.map((v, i) => (stacked ? baseline[i] + v : v));
          const areaD = [
            ...tops.map((v, i) => `${i === 0 ? 'M' : 'L'} ${xAt(i)} ${yAt(v)}`),
            ...(stacked ? baseline.map((v, i) => `L ${xAt(n - 1 - i)} ${yAt(baseline[n - 1 - i])}`) : [`L ${xAt(n - 1)} ${yAt(0)}`, `L ${xAt(0)} ${yAt(0)}`]),
            'Z',
          ].join(' ');
          const lineD = tops.map((v, i) => `${i === 0 ? 'M' : 'L'} ${xAt(i)} ${yAt(v)}`).join(' ');
          if (stacked) s.data.forEach((v, i) => { baseline[i] += v; });
          return (
            <g key={si} className="ev2-areac__area" style={{ animationDelay: `${si * 120}ms` }}>
              <path d={areaD} fill={`url(#${uid}-g${si})`} />
              <path className="ev2-areac__line" d={lineD} stroke={color} />
            </g>
          );
        })}
      </svg>
      {series.length > 1 && (
        <div className="ev2-areac__legend">
          {series.map((s, i) => <span className="ev2-areac__leg" key={i}><span className="ev2-areac__sw" style={{ background: s.color || EV2_AREA_PALETTE[i % EV2_AREA_PALETTE.length] }}></span>{s.title}</span>)}
        </div>
      )}
    </div>
  );
}
