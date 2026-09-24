// Enceladus v2 · SideNavigation — Cloudscape SideNavigation, deep re-brand.
const ev2SnCss = `
.ev2-sn{font-family:var(--font-body,'Inter',sans-serif);background:var(--enc-surface-alt,#1C2333);border-right:1px solid var(--v2-divider,rgba(61,155,168,.12));padding:12px 8px;min-width:220px;box-sizing:border-box}
.ev2-sn__header{padding:8px 12px 12px;border-bottom:1px solid var(--v2-divider,rgba(61,155,168,.12));margin-bottom:8px;display:flex;align-items:center;gap:9px}
.ev2-sn__mark{width:22px;height:22px;flex:0 0 auto;object-fit:contain}
.ev2-sn__brand{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:15px;color:var(--enc-seafoam,#C8DDD9);letter-spacing:.1em;text-decoration:none}
.ev2-sn__link{display:flex;align-items:center;gap:9px;padding:8px 12px;border-radius:6px;color:var(--enc-starlight,#EEF2F7);text-decoration:none;font-size:13.5px;cursor:pointer;transition:background var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),color var(--dur-fast,150ms) var(--ease-orbit);position:relative}
.ev2-sn__link:hover{background:rgba(61,155,168,.08)}
.ev2-sn__link--active{background:rgba(61,155,168,.12);color:var(--enc-teal-light,#7AC8D4);font-weight:500}
.ev2-sn__link--active::before{content:'';position:absolute;left:0;top:6px;bottom:6px;width:2px;background:var(--enc-teal,#3D9BA8);border-radius:1px}
.ev2-sn__count{margin-left:auto;font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-dust,#6B8A94)}
.ev2-sn__section{font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--enc-dust,#6B8A94);padding:14px 12px 5px}
.ev2-sn__divider{height:1px;background:var(--v2-divider,rgba(61,155,168,.12));margin:8px 4px}
.ev2-sn__icon{display:inline-flex;flex:0 0 auto}
@keyframes ev2-sn-spin{to{transform:rotate(360deg)}}
.ev2-sn__link--spin:active .ev2-sn__icon{animation:ev2-sn-spin .6s cubic-bezier(.4,0,.2,1)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-sn-css')){const s=document.createElement('style');s.id='ev2-sn-css';s.textContent=ev2SnCss;document.head.appendChild(s);}})();

export function SideNavigation({ header, items = [], activeHref, onFollow }) {
  return (
    <nav className="ev2-sn" aria-label="Side navigation">
      {header && (
        <div className="ev2-sn__header">
          {header.iconSrc && <img className="ev2-sn__mark" src={header.iconSrc} alt="" aria-hidden="true" />}
          <a className="ev2-sn__brand" href={header.href || '#'}>{header.text}</a>
        </div>
      )}
      {items.map((it, i) => {
        if (it.type === 'divider') return <div className="ev2-sn__divider" key={i}></div>;
        if (it.type === 'section') return <div className="ev2-sn__section" key={i}>{it.text}</div>;
        const active = it.href === activeHref;
        const classes = `ev2-sn__link${active ? ' ev2-sn__link--active' : ''}${it.spin ? ' ev2-sn__link--spin' : ''}`;
        return (
          <a key={i} href={it.href || '#'} className={classes}
            aria-current={active ? 'page' : undefined}
            onClick={(e) => { if (onFollow) { e.preventDefault(); onFollow({ detail: { href: it.href, text: it.text } }); } }}>
            {it.icon && <span className="ev2-sn__icon" aria-hidden="true">{it.icon}</span>}
            {it.text}
            {it.count != null && <span className="ev2-sn__count">{it.count}</span>}
          </a>
        );
      })}
    </nav>
  );
}
