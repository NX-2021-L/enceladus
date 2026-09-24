// Enceladus v2 · Slider — Cloudscape Slider, deep re-brand.
const ev2SliderCss = `
.ev2-slider{font-family:var(--font-body,'Inter',sans-serif);width:100%}
.ev2-slider__row{display:flex;align-items:center;gap:12px}
.ev2-slider__input{-webkit-appearance:none;appearance:none;flex:1;height:6px;border-radius:3px;outline:none;cursor:pointer;background:var(--enc-slate,#2E4D5C)}
.ev2-slider__input:focus-visible{box-shadow:var(--v2-focus-ring)}
.ev2-slider__input::-webkit-slider-thumb{-webkit-appearance:none;appearance:none;width:16px;height:16px;border-radius:50%;background:var(--enc-teal,#3D9BA8);border:2px solid var(--enc-void,#0A0A0F);cursor:pointer;box-shadow:0 0 0 1px var(--enc-teal,#3D9BA8);transition:box-shadow var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-slider__input::-webkit-slider-thumb:hover{box-shadow:0 0 0 1px var(--enc-teal,#3D9BA8),0 0 12px rgba(61,155,168,.5)}
.ev2-slider__input::-moz-range-thumb{width:16px;height:16px;border-radius:50%;background:var(--enc-teal,#3D9BA8);border:2px solid var(--enc-void,#0A0A0F);cursor:pointer}
.ev2-slider__value{font-family:var(--font-mono,monospace);font-size:13px;color:var(--enc-teal,#3D9BA8);min-width:44px;text-align:right;font-variant-numeric:tabular-nums}
.ev2-slider__ticks{display:flex;justify-content:space-between;margin-top:4px;font-family:var(--font-mono,monospace);font-size:10px;color:var(--enc-dust,#6B8A94)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-slider-css')){const s=document.createElement('style');s.id='ev2-slider-css';s.textContent=ev2SliderCss;document.head.appendChild(s);}})();

export function Slider({ value = 0, min = 0, max = 100, step = 1, disabled = false, valueFormatter, ticks, onChange, ariaLabel }) {
  const pct = ((value - min) / (max - min)) * 100;
  const trackStyle = { background: `linear-gradient(90deg, var(--enc-teal,#3D9BA8) ${pct}%, var(--enc-slate,#2E4D5C) ${pct}%)` };
  return (
    <div className="ev2-slider">
      <div className="ev2-slider__row">
        <input className="ev2-slider__input" type="range" min={min} max={max} step={step} value={value}
          disabled={disabled} style={trackStyle} aria-label={ariaLabel}
          onChange={(e) => onChange && onChange({ detail: { value: Number(e.target.value) } })} />
        <span className="ev2-slider__value">{valueFormatter ? valueFormatter(value) : value}</span>
      </div>
      {ticks && (
        <div className="ev2-slider__ticks">
          {ticks.map((t, i) => <span key={i}>{t}</span>)}
        </div>
      )}
    </div>
  );
}
