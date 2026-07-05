// Enceladus v2 · TextFilter — Cloudscape TextFilter, deep re-brand.
const ev2TfCss = `
.ev2-tf{display:flex;flex-direction:column;gap:4px;font-family:var(--font-body,'Inter',sans-serif);width:100%;max-width:420px}
.ev2-tf__count{font-family:var(--font-mono,monospace);font-size:11.5px;color:var(--enc-dust,#6B8A94)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-tf-css')){const s=document.createElement('style');s.id='ev2-tf-css';s.textContent=ev2TfCss;document.head.appendChild(s);}})();

export function TextFilter({ filteringText = '', placeholder = 'Filter records', countText, onChange }) {
  const NS = (typeof window !== 'undefined' && window.EnceladusDesignSystem_7eb1fe) || {};
  const InputCmp = NS.Input;
  const searchIcon = React.createElement('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.75, strokeLinecap: 'round' },
    React.createElement('circle', { cx: 11, cy: 11, r: 7 }), React.createElement('line', { x1: 21, y1: 21, x2: 16.65, y2: 16.65 }));
  return (
    <div className="ev2-tf">
      {InputCmp
        ? <InputCmp value={filteringText} placeholder={placeholder} type="search" icon={searchIcon} ariaLabel="Filter" onChange={(ev) => onChange && onChange({ detail: { filteringText: ev.detail.value } })} />
        : <input value={filteringText} placeholder={placeholder} onChange={(ev) => onChange && onChange({ detail: { filteringText: ev.target.value } })}
            style={{ width: '100%', height: 32, padding: '0 12px', background: '#0D1220', border: '1px solid rgba(61,155,168,.25)', borderRadius: 6, color: '#EEF2F7', fontSize: 14, boxSizing: 'border-box' }} />}
      {countText && <span className="ev2-tf__count">{countText}</span>}
    </div>
  );
}
