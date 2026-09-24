// Enceladus v2 · Cards — Cloudscape Cards, deep re-brand.
const ev2CardsCss = `
.ev2-cards{font-family:var(--font-body,'Inter',sans-serif)}
.ev2-cards__tools{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}
.ev2-cards__grid{display:grid;gap:12px}
.ev2-card{position:relative;background:var(--enc-surface,#111827);border:1px solid var(--v2-panel-border,rgba(61,155,168,.2));border-radius:var(--v2-panel-radius,8px);padding:14px 16px;transition:border-color var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-card:hover{border-color:rgba(61,155,168,.42)}
.ev2-card--sel{border-color:var(--enc-teal,#3D9BA8);background:rgba(61,155,168,.06)}
.ev2-card__head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:8px}
.ev2-card__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;color:var(--enc-seafoam,#C8DDD9);line-height:1.35}
.ev2-card__cb{width:15px;height:15px;border-radius:3px;border:1px solid var(--v2-field-border,rgba(61,155,168,.4));background:var(--v2-field-bg,#0D1220);display:inline-flex;align-items:center;justify-content:center;cursor:pointer;flex:0 0 auto}
.ev2-card__cb--on{background:var(--enc-teal,#3D9BA8);border-color:var(--enc-teal,#3D9BA8)}
.ev2-card__cb svg{width:10px;height:10px;stroke:var(--enc-void,#0A0A0F);stroke-width:3;fill:none}
.ev2-card__section{margin-top:8px}
.ev2-card__label{font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.06em;color:var(--enc-dust,#6B8A94);margin-bottom:2px}
.ev2-card__value{font-size:13px;color:var(--enc-starlight,#EEF2F7)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-cards-css')){const s=document.createElement('style');s.id='ev2-cards-css';s.textContent=ev2CardsCss;document.head.appendChild(s);}})();

export function Cards({ items = [], cardDefinition = {}, header, columns = 3, selectionType, selectedItems = [], trackBy = 'id', onSelectionChange }) {
  const idOf = (it) => it[trackBy];
  const selIds = selectedItems.map(idOf);
  const toggle = (it) => {
    if (selectionType === 'single') { onSelectionChange && onSelectionChange({ detail: { selectedItems: [it] } }); return; }
    const next = selIds.includes(idOf(it)) ? selectedItems.filter((s) => idOf(s) !== idOf(it)) : [...selectedItems, it];
    onSelectionChange && onSelectionChange({ detail: { selectedItems: next } });
  };
  return (
    <div className="ev2-cards">
      {header && <div className="ev2-cards__tools">{header}</div>}
      <div className="ev2-cards__grid" style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>
        {items.map((it) => {
          const sel = selIds.includes(idOf(it));
          return (
            <div key={idOf(it)} className={`ev2-card${sel ? ' ev2-card--sel' : ''}`}>
              <div className="ev2-card__head">
                <span className="ev2-card__title">{cardDefinition.header ? cardDefinition.header(it) : idOf(it)}</span>
                {selectionType && (
                  <span className={`ev2-card__cb${sel ? ' ev2-card__cb--on' : ''}`} onClick={() => toggle(it)} aria-hidden="true">
                    {sel && <svg viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 12 10 18 20 6"/></svg>}
                  </span>
                )}
              </div>
              {(cardDefinition.sections || []).map((sec, i) => (
                <div className="ev2-card__section" key={sec.id || i}>
                  {sec.header && <div className="ev2-card__label">{sec.header}</div>}
                  <div className="ev2-card__value">{sec.content(it)}</div>
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
