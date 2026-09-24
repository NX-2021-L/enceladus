// Enceladus v2 · Header — Cloudscape Header, deep re-brand.
const ev2HeaderCss = `
.ev2-header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;font-family:var(--font-heading,'Space Grotesk',sans-serif)}
.ev2-header__title{margin:0;color:var(--enc-seafoam,#C8DDD9);font-weight:700;line-height:1.25;display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.ev2-header--h1 .ev2-header__title{font-size:28px}
.ev2-header--h2 .ev2-header__title{font-size:20px}
.ev2-header--h3 .ev2-header__title{font-size:16px;font-weight:500}
.ev2-header__counter{font-family:var(--font-mono,monospace);font-weight:400;font-size:.7em;color:var(--enc-dust,#6B8A94)}
.ev2-header__rid{font-family:var(--font-mono,monospace);font-weight:400;font-size:.6em;color:var(--enc-teal,#3D9BA8);opacity:.85}
.ev2-header__desc{margin:4px 0 0;font-family:var(--font-body,'Inter',sans-serif);font-size:13px;line-height:1.55;color:var(--enc-dust,#6B8A94);font-weight:400}
.ev2-header__actions{display:flex;gap:8px;flex:0 0 auto;align-items:center}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-header-css')){const s=document.createElement('style');s.id='ev2-header-css';s.textContent=ev2HeaderCss;document.head.appendChild(s);}})();

export function Header({ variant = 'h2', counter, recordId, description, actions, children }) {
  const Tag = variant;
  return (
    <div className={`ev2-header ev2-header--${variant}`}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <Tag className="ev2-header__title">
          {children}
          {counter && <span className="ev2-header__counter">{counter}</span>}
          {recordId && <span className="ev2-header__rid">{recordId}</span>}
        </Tag>
        {description && <p className="ev2-header__desc">{description}</p>}
      </div>
      {actions && <div className="ev2-header__actions">{actions}</div>}
    </div>
  );
}
