// Enceladus v2 · Table — Cloudscape Table, deep re-brand.
const ev2TableCss = `
.ev2-table{background:var(--enc-surface,#111827);border:1px solid var(--v2-panel-border,rgba(61,155,168,.2));border-radius:var(--v2-panel-radius,8px);overflow:hidden;font-family:var(--font-body,'Inter',sans-serif)}
.ev2-table__tools{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 18px;border-bottom:1px solid var(--v2-divider,rgba(61,155,168,.12))}
.ev2-table__scroll{overflow-x:auto}
.ev2-table table{width:100%;border-collapse:collapse}
.ev2-table thead th{text-align:left;font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--enc-dust,#6B8A94);padding:10px 16px;border-bottom:1px solid var(--v2-divider,rgba(61,155,168,.12));white-space:nowrap;background:var(--enc-surface-alt,#1C2333)}
.ev2-table th.ev2-table__sortable{cursor:pointer;user-select:none}
.ev2-table th.ev2-table__sortable:hover{color:var(--enc-teal-light,#7AC8D4)}
.ev2-table__sortarrow{margin-left:5px;font-size:9px;opacity:.9}
.ev2-table tbody td{padding:11px 16px;font-size:13.5px;color:var(--enc-starlight,#EEF2F7);border-bottom:1px solid rgba(61,155,168,.07);vertical-align:middle}
.ev2-table tbody tr{transition:background var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-table tbody tr:hover{background:rgba(61,155,168,.05)}
.ev2-table tbody tr:last-child td{border-bottom:none}
.ev2-table tbody tr.ev2-table__row--sel{background:rgba(61,155,168,.1)}
.ev2-table__sel{width:40px;text-align:center}
.ev2-table__cb{width:15px;height:15px;border-radius:3px;border:1px solid var(--v2-field-border,rgba(61,155,168,.4));background:var(--v2-field-bg,#0D1220);display:inline-flex;align-items:center;justify-content:center;cursor:pointer;vertical-align:middle}
.ev2-table__cb--on{background:var(--enc-teal,#3D9BA8);border-color:var(--enc-teal,#3D9BA8)}
.ev2-table__cb svg{width:10px;height:10px;stroke:var(--enc-void,#0A0A0F);stroke-width:3;fill:none}
.ev2-table__empty{padding:36px;text-align:center;color:var(--enc-dust,#6B8A94);font-size:14px}
.ev2-table__count{font-family:var(--font-mono,monospace);font-size:12px;color:var(--enc-dust,#6B8A94)}
.ev2-table__mono{font-family:var(--font-mono,monospace);font-size:12.5px;color:var(--enc-teal,#3D9BA8)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-table-css')){const s=document.createElement('style');s.id='ev2-table-css';s.textContent=ev2TableCss;document.head.appendChild(s);}})();

export function Table({ columnDefinitions = [], items = [], header, footer, selectionType, selectedItems = [], trackBy = 'id', sortingColumn, sortingDescending = false, empty = 'No records', onSelectionChange, onSortingChange }) {
  const idOf = (it) => it[trackBy];
  const selIds = selectedItems.map(idOf);
  const allSel = items.length > 0 && items.every((it) => selIds.includes(idOf(it)));
  const toggleRow = (it) => {
    if (selectionType === 'single') { onSelectionChange && onSelectionChange({ detail: { selectedItems: [it] } }); return; }
    const next = selIds.includes(idOf(it)) ? selectedItems.filter((s) => idOf(s) !== idOf(it)) : [...selectedItems, it];
    onSelectionChange && onSelectionChange({ detail: { selectedItems: next } });
  };
  const toggleAll = () => onSelectionChange && onSelectionChange({ detail: { selectedItems: allSel ? [] : [...items] } });
  const check = (on) => (
    <span className={`ev2-table__cb${on ? ' ev2-table__cb--on' : ''}`} aria-hidden="true">
      {on && <svg viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 12 10 18 20 6"/></svg>}
    </span>
  );
  return (
    <div className="ev2-table">
      {header && <div className="ev2-table__tools">{header}</div>}
      <div className="ev2-table__scroll">
        <table role="table">
          <thead>
            <tr>
              {selectionType && (
                <th className="ev2-table__sel">
                  {selectionType === 'multi' && <span onClick={toggleAll} style={{ cursor: 'pointer' }}>{check(allSel)}</span>}
                </th>
              )}
              {columnDefinitions.map((col) => {
                const active = sortingColumn && sortingColumn.sortingField === col.sortingField;
                return (
                  <th key={col.id} className={col.sortingField ? 'ev2-table__sortable' : ''}
                    onClick={col.sortingField ? () => onSortingChange && onSortingChange({ detail: { sortingColumn: { sortingField: col.sortingField }, isDescending: active ? !sortingDescending : false } }) : undefined}>
                    {col.header}
                    {active && <span className="ev2-table__sortarrow">{sortingDescending ? '▼' : '▲'}</span>}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr><td className="ev2-table__empty" colSpan={columnDefinitions.length + (selectionType ? 1 : 0)}>{empty}</td></tr>
            )}
            {items.map((it) => {
              const sel = selIds.includes(idOf(it));
              return (
                <tr key={idOf(it)} className={sel ? 'ev2-table__row--sel' : ''}>
                  {selectionType && (
                    <td className="ev2-table__sel"><span onClick={() => toggleRow(it)} style={{ cursor: 'pointer' }}>{check(sel)}</span></td>
                  )}
                  {columnDefinitions.map((col) => <td key={col.id}>{col.cell(it)}</td>)}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {footer && <div className="ev2-table__tools" style={{ borderBottom: 'none', borderTop: '1px solid var(--v2-divider,rgba(61,155,168,.12))' }}>{footer}</div>}
    </div>
  );
}
