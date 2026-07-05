// Enceladus v2 · BreadcrumbGroup — Cloudscape BreadcrumbGroup, deep re-brand.
const ev2BcCss = `
.ev2-bc{display:flex;align-items:center;flex-wrap:wrap;gap:2px;font-family:var(--font-body,'Inter',sans-serif);font-size:13px}
.ev2-bc__item{color:var(--enc-teal-light,#7AC8D4);text-decoration:none;padding:2px 4px;border-radius:3px;transition:color var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-bc__item:hover{color:var(--enc-seafoam,#C8DDD9)}
.ev2-bc__item--current{color:var(--enc-dust,#6B8A94);pointer-events:none}
.ev2-bc__item--mono{font-family:var(--font-mono,monospace);font-size:12px}
.ev2-bc__sep{color:var(--enc-slate,#2E4D5C);font-size:12px;user-select:none}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-bc-css')){const s=document.createElement('style');s.id='ev2-bc-css';s.textContent=ev2BcCss;document.head.appendChild(s);}})();

export function BreadcrumbGroup({ items = [], onFollow }) {
  return (
    <nav className="ev2-bc" aria-label="Breadcrumb">
      {items.map((it, i) => {
        const last = i === items.length - 1;
        const isMono = /^[A-Z]{2,4}-[A-Z]{3}-/.test(String(it.text));
        return (
          <React.Fragment key={i}>
            <a href={it.href || '#'} aria-current={last ? 'page' : undefined}
              className={`ev2-bc__item${last ? ' ev2-bc__item--current' : ''}${isMono ? ' ev2-bc__item--mono' : ''}`}
              onClick={(e) => { if (!last && onFollow) { e.preventDefault(); onFollow({ detail: { item: it, href: it.href } }); } }}>
              {it.text}
            </a>
            {!last && <span className="ev2-bc__sep" aria-hidden="true">/</span>}
          </React.Fragment>
        );
      })}
    </nav>
  );
}
