// Enceladus v2 · TokenGroup — Cloudscape TokenGroup, deep re-brand.
const ev2TokenCss = `
.ev2-tokengroup{display:flex;flex-wrap:wrap;gap:8px;font-family:var(--font-body,'Inter',sans-serif)}
.ev2-token{display:inline-flex;align-items:center;gap:8px;padding:4px 6px 4px 11px;background:rgba(61,155,168,.08);border:1px solid var(--v2-field-border,rgba(61,155,168,.3));border-radius:var(--v2-chip-radius,4px);font-size:13px;color:var(--enc-starlight,#EEF2F7);transition:border-color var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-token:hover{border-color:rgba(61,155,168,.5)}
.ev2-token--disabled{opacity:.45}
.ev2-token__label{white-space:nowrap}
.ev2-token__label--mono{font-family:var(--font-mono,monospace);font-size:12px;color:var(--enc-teal,#3D9BA8)}
.ev2-token__x{appearance:none;border:none;background:none;color:var(--enc-dust,#6B8A94);cursor:pointer;font-size:14px;line-height:1;padding:2px 4px;border-radius:3px;transition:color var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-token__x:hover{color:var(--enc-crimson,#C85060)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-token-css')){const s=document.createElement('style');s.id='ev2-token-css';s.textContent=ev2TokenCss;document.head.appendChild(s);}})();

export function TokenGroup({ items = [], onDismiss, mono = false }) {
  const [removed, setRemoved] = React.useState({});
  return (
    <div className="ev2-tokengroup">
      {items.map((it, i) => {
        if (removed[i]) return null;
        return (
          <span key={i} className={`ev2-token${it.disabled ? ' ev2-token--disabled' : ''}`}>
            <span className={`ev2-token__label${mono || it.mono ? ' ev2-token__label--mono' : ''}`}>{it.label}</span>
            {!it.disabled && (
              <button className="ev2-token__x" aria-label={`Remove ${it.label}`}
                onClick={() => { setRemoved((r) => ({ ...r, [i]: true })); onDismiss && onDismiss({ detail: { itemIndex: i } }); }}>✕</button>
            )}
          </span>
        );
      })}
    </div>
  );
}
