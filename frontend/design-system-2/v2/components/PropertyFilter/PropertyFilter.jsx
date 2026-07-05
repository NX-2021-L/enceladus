// Enceladus v2 · PropertyFilter — Cloudscape PropertyFilter, deep re-brand.
const ev2PfCss = `
.ev2-pf{font-family:var(--font-body,'Inter',sans-serif);width:100%}
.ev2-pf__bar{display:flex;align-items:center;gap:6px;flex-wrap:wrap;min-height:var(--v2-control-height,32px);padding:4px 8px;background:var(--v2-field-bg,#0D1220);border:1px solid var(--v2-field-border,rgba(61,155,168,.25));border-radius:var(--v2-control-radius,6px);transition:border-color var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),box-shadow var(--dur-base,200ms) var(--ease-orbit)}
.ev2-pf--focused .ev2-pf__bar{border-color:var(--v2-field-border-focus,#3D9BA8);box-shadow:var(--v2-focus-ring)}
.ev2-pf__token{display:inline-flex;align-items:center;gap:6px;padding:2px 6px 2px 9px;background:rgba(61,155,168,.12);border:1px solid rgba(61,155,168,.35);border-radius:4px;font-family:var(--font-mono,monospace);font-size:12px;color:var(--enc-teal-light,#7AC8D4)}
.ev2-pf__token b{color:var(--enc-seafoam,#C8DDD9);font-weight:500}
.ev2-pf__token .op{color:var(--enc-dust,#6B8A94)}
.ev2-pf__token button{appearance:none;border:none;background:none;color:inherit;cursor:pointer;font-size:12px;opacity:.7;padding:1px 2px}
.ev2-pf__token button:hover{opacity:1;color:var(--enc-crimson,#C85060)}
.ev2-pf__input{flex:1;min-width:120px;background:none;border:none;outline:none;color:var(--enc-starlight,#EEF2F7);font-size:14px;font-family:inherit;padding:3px 2px}
.ev2-pf__input::placeholder{color:var(--v2-field-placeholder,#4A5E68)}
.ev2-pf__clear{appearance:none;border:none;background:none;color:var(--enc-dust,#6B8A94);cursor:pointer;font-size:12px;font-family:var(--font-body,sans-serif);padding:2px 6px;border-radius:4px}
.ev2-pf__clear:hover{color:var(--enc-teal-light,#7AC8D4)}
.ev2-pf__hint{margin-top:5px;font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-dust,#6B8A94)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-pf-css')){const s=document.createElement('style');s.id='ev2-pf-css';s.textContent=ev2PfCss;document.head.appendChild(s);}})();

export function PropertyFilter({ query = { tokens: [], operation: 'and' }, filteringProperties = [], placeholder = 'Filter by property or value', hint, onChange }) {
  const [focused, setFocused] = React.useState(false);
  const [text, setText] = React.useState('');
  const tokens = query.tokens || [];
  const removeToken = (i) => onChange && onChange({ detail: { ...query, tokens: tokens.filter((_, j) => j !== i) } });
  const addFromText = () => {
    const m = text.match(/^\s*([\w.]+)\s*(=|!=|:|>=|<=|>|<)\s*(.+?)\s*$/);
    if (!m) return;
    const next = [...tokens, { propertyKey: m[1], operator: m[2], value: m[3] }];
    onChange && onChange({ detail: { ...query, tokens: next } });
    setText('');
  };
  return (
    <div className={`ev2-pf${focused ? ' ev2-pf--focused' : ''}`}>
      <div className="ev2-pf__bar">
        {tokens.map((t, i) => (
          <span className="ev2-pf__token" key={i}>
            <b>{t.propertyKey}</b><span className="op">{t.operator}</span>{t.value}
            <button aria-label="Remove filter" onClick={() => removeToken(i)}>✕</button>
          </span>
        ))}
        <input className="ev2-pf__input" value={text} placeholder={tokens.length ? '' : placeholder}
          onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addFromText(); } }} />
        {tokens.length > 0 && <button className="ev2-pf__clear" onClick={() => onChange && onChange({ detail: { ...query, tokens: [] } })}>Clear</button>}
      </div>
      {(hint || filteringProperties.length > 0) && (
        <div className="ev2-pf__hint">{hint || `properties: ${filteringProperties.map((p) => p.key).join(', ')}`}</div>
      )}
    </div>
  );
}
