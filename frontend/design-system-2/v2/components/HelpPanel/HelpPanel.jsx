// Enceladus v2 · HelpPanel — Cloudscape HelpPanel, deep re-brand.
const ev2HpCss = `
.ev2-help{font-family:var(--font-body,'Inter',sans-serif);background:var(--enc-surface,#111827);border-left:1px solid var(--v2-divider,rgba(61,155,168,.12));padding:20px 22px;min-width:280px;box-sizing:border-box;height:100%;overflow-y:auto}
.ev2-help__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:16px;color:var(--enc-seafoam,#C8DDD9);margin:0 0 14px;padding-bottom:10px;border-bottom:1px solid var(--v2-divider,rgba(61,155,168,.12))}
.ev2-help__body{font-size:13.5px;line-height:1.65;color:var(--enc-starlight,#EEF2F7)}
.ev2-help__body p{margin:0 0 12px}
.ev2-help__body h4{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--enc-teal,#3D9BA8);margin:18px 0 6px}
.ev2-help__body code{font-family:var(--font-mono,monospace);font-size:12px;background:var(--enc-slate,#2E4D5C);color:var(--enc-teal-light,#7AC8D4);padding:1px 6px;border-radius:3px}
.ev2-help__footer{margin-top:18px;padding-top:14px;border-top:1px solid var(--v2-divider,rgba(61,155,168,.12))}
.ev2-help__footer h4{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--enc-dust,#6B8A94);margin:0 0 8px}
.ev2-help__link{display:block;color:var(--enc-teal-light,#7AC8D4);text-decoration:none;font-size:13px;padding:3px 0}
.ev2-help__link:hover{color:var(--enc-seafoam,#C8DDD9)}
.ev2-help__link::after{content:' ↗';font-size:.8em;opacity:.6}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-hp-css')){const s=document.createElement('style');s.id='ev2-hp-css';s.textContent=ev2HpCss;document.head.appendChild(s);}})();

export function HelpPanel({ header, footer, links, children }) {
  return (
    <aside className="ev2-help" aria-label="Help panel">
      {header && <h2 className="ev2-help__title">{header}</h2>}
      <div className="ev2-help__body">{children}</div>
      {(footer || links) && (
        <div className="ev2-help__footer">
          {footer}
          {links && (
            <React.Fragment>
              <h4>Learn more</h4>
              {links.map((l, i) => <a className="ev2-help__link" key={i} href={l.href || '#'}>{l.text}</a>)}
            </React.Fragment>
          )}
        </div>
      )}
    </aside>
  );
}
