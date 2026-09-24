// Enceladus v2 · KeyValuePairs — Cloudscape KeyValuePairs, deep re-brand.
const ev2KvCss = `
.ev2-kv{display:grid;gap:16px 24px;font-family:var(--font-body,'Inter',sans-serif)}
.ev2-kv__pair{min-width:0}
.ev2-kv__key{font-size:11px;font-weight:500;text-transform:uppercase;letter-spacing:.06em;color:var(--enc-dust,#6B8A94);margin-bottom:3px;display:flex;align-items:center;gap:5px}
.ev2-kv__value{font-size:14px;color:var(--enc-starlight,#EEF2F7);line-height:1.4}
.ev2-kv__value--mono{font-family:var(--font-mono,monospace);font-size:13px;color:var(--enc-teal,#3D9BA8);font-variant-numeric:tabular-nums}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-kv-css')){const s=document.createElement('style');s.id='ev2-kv-css';s.textContent=ev2KvCss;document.head.appendChild(s);}})();

export function KeyValuePairs({ items = [], columns = 3 }) {
  return (
    <div className="ev2-kv" style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>
      {items.map((it, i) => (
        <div className="ev2-kv__pair" key={i}>
          <div className="ev2-kv__key">{it.label}</div>
          <div className={`ev2-kv__value${it.mono ? ' ev2-kv__value--mono' : ''}`}>{it.value}</div>
        </div>
      ))}
    </div>
  );
}
