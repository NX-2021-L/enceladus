// Enceladus v2 · Tiles — Cloudscape Tiles, deep re-brand.
const ev2TilesCss = `
.ev2-tiles{display:grid;gap:12px;font-family:var(--font-body,'Inter',sans-serif)}
.ev2-tile{position:relative;padding:14px 16px;border:1px solid var(--v2-panel-border,rgba(61,155,168,.2));border-radius:var(--v2-panel-radius,8px);background:var(--enc-surface,#111827);cursor:pointer;transition:border-color var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),background var(--dur-base,200ms) var(--ease-orbit)}
.ev2-tile:hover{border-color:rgba(61,155,168,.45)}
.ev2-tile--selected{border-color:var(--enc-teal,#3D9BA8);background:rgba(61,155,168,.08)}
.ev2-tile--disabled{opacity:.45;cursor:not-allowed}
.ev2-tile__top{display:flex;align-items:center;gap:9px;margin-bottom:4px}
.ev2-tile__dot{width:15px;height:15px;border-radius:50%;border:1px solid var(--v2-field-border,rgba(61,155,168,.4));display:flex;align-items:center;justify-content:center;flex:0 0 auto}
.ev2-tile--selected .ev2-tile__dot{border-color:var(--enc-teal,#3D9BA8)}
.ev2-tile--selected .ev2-tile__dot::after{content:'';width:7px;height:7px;border-radius:50%;background:var(--enc-teal,#3D9BA8)}
.ev2-tile__label{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;color:var(--enc-seafoam,#C8DDD9)}
.ev2-tile__desc{font-size:12.5px;line-height:1.5;color:var(--enc-dust,#6B8A94);padding-left:24px}
.ev2-tile input{position:absolute;opacity:0;width:0;height:0}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-tiles-css')){const s=document.createElement('style');s.id='ev2-tiles-css';s.textContent=ev2TilesCss;document.head.appendChild(s);}})();

export function Tiles({ value, items = [], columns = 2, onChange, name }) {
  const groupName = name || React.useId();
  return (
    <div className="ev2-tiles" role="radiogroup" style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>
      {items.map((it) => {
        const selected = it.value === value;
        const cls = ['ev2-tile', selected ? 'ev2-tile--selected' : '', it.disabled ? 'ev2-tile--disabled' : ''].filter(Boolean).join(' ');
        return (
          <label key={it.value} className={cls}>
            <input type="radio" name={groupName} checked={selected} disabled={it.disabled}
              onChange={() => onChange && onChange({ detail: { value: it.value } })} />
            <div className="ev2-tile__top">
              <span className="ev2-tile__dot" aria-hidden="true"></span>
              <span className="ev2-tile__label">{it.label}</span>
            </div>
            {it.description && <div className="ev2-tile__desc">{it.description}</div>}
          </label>
        );
      })}
    </div>
  );
}
