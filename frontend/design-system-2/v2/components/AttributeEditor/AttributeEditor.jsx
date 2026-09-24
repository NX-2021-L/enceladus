// Enceladus v2 · AttributeEditor — Cloudscape AttributeEditor, deep re-brand.
const ev2AttrCss = `
.ev2-attr{font-family:var(--font-body,'Inter',sans-serif)}
.ev2-attr__row{display:flex;gap:10px;align-items:flex-start;margin-bottom:10px}
.ev2-attr__cell{flex:1;min-width:0}
.ev2-attr__label{font-size:11px;font-weight:500;text-transform:uppercase;letter-spacing:.06em;color:var(--enc-dust,#6B8A94);margin-bottom:3px;display:block}
.ev2-attr__row:not(:first-child) .ev2-attr__label{display:none}
.ev2-attr__field{width:100%;height:var(--v2-control-height,32px);padding:0 10px;background:var(--v2-field-bg,#0D1220);border:1px solid var(--v2-field-border,rgba(61,155,168,.25));border-radius:var(--v2-control-radius,6px);color:var(--enc-starlight,#EEF2F7);font-family:var(--font-mono,monospace);font-size:13px;outline:none;box-sizing:border-box;transition:border-color var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-attr__field:focus{border-color:var(--v2-field-border-focus,#3D9BA8);box-shadow:var(--v2-focus-ring)}
.ev2-attr__remove{height:32px;margin-top:0;align-self:flex-end;appearance:none;border:1px solid rgba(200,80,96,.4);background:rgba(200,80,96,.08);color:var(--enc-crimson,#C85060);border-radius:6px;padding:0 12px;font-size:13px;cursor:pointer;transition:background var(--dur-fast,150ms) var(--ease-orbit);white-space:nowrap}
.ev2-attr__remove:hover{background:rgba(200,80,96,.18)}
.ev2-attr__add{margin-top:4px;appearance:none;border:1px solid var(--enc-teal,#3D9BA8);background:none;color:var(--enc-teal,#3D9BA8);border-radius:6px;padding:6px 14px;font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:13px;cursor:pointer;transition:all var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-attr__add:hover{background:rgba(61,155,168,.08);color:var(--enc-teal-light,#7AC8D4)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-attr-css')){const s=document.createElement('style');s.id='ev2-attr-css';s.textContent=ev2AttrCss;document.head.appendChild(s);}})();

export function AttributeEditor({ items = [], addButtonText = 'Add relationship', removeButtonText = 'Remove', keyLabel = 'Edge', valueLabel = 'Target', onAddButtonClick, onRemoveButtonClick, onChange }) {
  const update = (i, field, val) => {
    const next = items.map((it, j) => (j === i ? { ...it, [field]: val } : it));
    onChange && onChange({ detail: { items: next } });
  };
  return (
    <div className="ev2-attr">
      {items.map((it, i) => (
        <div className="ev2-attr__row" key={i}>
          <div className="ev2-attr__cell">
            <span className="ev2-attr__label">{keyLabel}</span>
            <input className="ev2-attr__field" value={it.key || ''} onChange={(e) => update(i, 'key', e.target.value)} aria-label={`${keyLabel} ${i + 1}`} />
          </div>
          <div className="ev2-attr__cell">
            <span className="ev2-attr__label">{valueLabel}</span>
            <input className="ev2-attr__field" value={it.value || ''} onChange={(e) => update(i, 'value', e.target.value)} aria-label={`${valueLabel} ${i + 1}`} />
          </div>
          <button className="ev2-attr__remove" onClick={() => onRemoveButtonClick && onRemoveButtonClick({ detail: { itemIndex: i } })}>{removeButtonText}</button>
        </div>
      ))}
      <button className="ev2-attr__add" onClick={() => onAddButtonClick && onAddButtonClick()}>{addButtonText}</button>
    </div>
  );
}
