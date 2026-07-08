// Enceladus v2 · TopNavigation — Cloudscape TopNavigation, deep re-brand.
const ev2TnCss = `
.ev2-tn{display:flex;align-items:center;gap:16px;height:52px;padding:0 20px;background:rgba(10,10,15,.85);backdrop-filter:blur(14px);border-bottom:1px solid var(--v2-divider,rgba(61,155,168,.12));font-family:var(--font-body,'Inter',sans-serif)}
.ev2-tn__brand{display:flex;align-items:center;gap:9px;text-decoration:none;flex:0 0 auto}
.ev2-tn__mark{width:24px;height:24px;flex:0 0 auto}
img.ev2-tn__mark{object-fit:contain}
.ev2-tn__title{font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:15px;letter-spacing:.12em;color:var(--enc-seafoam,#C8DDD9)}
.ev2-tn__version{font-family:var(--font-mono,monospace);font-size:10.5px;color:var(--enc-dust,#6B8A94);border:1px solid rgba(61,155,168,.2);border-radius:4px;padding:1px 6px;flex:0 0 auto}
.ev2-tn__spacer{flex:1}
.ev2-tn__util{display:flex;align-items:center;gap:4px}
.ev2-tn__btn{display:flex;align-items:center;gap:7px;padding:6px 11px;border-radius:6px;background:none;border:none;color:var(--enc-starlight,#EEF2F7);font-size:13px;cursor:pointer;transition:background var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1));font-family:inherit}
.ev2-tn__btn:hover{background:rgba(61,155,168,.1);color:var(--enc-teal-light,#7AC8D4)}
.ev2-tn__badge{font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-teal,#3D9BA8)}
.ev2-tn__avatar{width:26px;height:26px;border-radius:50%;background:var(--enc-teal,#3D9BA8);color:var(--enc-void,#0A0A0F);display:flex;align-items:center;justify-content:center;font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:700;font-size:12px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-tn-css')){const s=document.createElement('style');s.id='ev2-tn-css';s.textContent=ev2TnCss;document.head.appendChild(s);}})();

export function TopNavigation({ identity = {}, utilities = [] }) {
  return (
    <header className="ev2-tn">
      <a className="ev2-tn__brand" href={identity.href || '#'}>
        {identity.iconSrc
          ? <img className="ev2-tn__mark" src={identity.iconSrc} alt="" aria-hidden="true" />
          : (
            <svg className="ev2-tn__mark" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <circle cx="12" cy="12" r="10" stroke="#3D9BA8" strokeWidth="1.6"/>
              <circle cx="12" cy="12" r="5.5" stroke="#7AC8D4" strokeWidth="1" opacity="0.6"/>
              <circle cx="12" cy="12" r="2.2" fill="#8A8CB5"/>
            </svg>
          )}
        <span className="ev2-tn__title">{identity.title || 'ENCELADUS'}</span>
      </a>
      {identity.version
        ? <span className="ev2-tn__version" title="Build version">{identity.version}</span>
        : null}
      <div className="ev2-tn__spacer"></div>
      <div className="ev2-tn__util">
        {utilities.map((u, i) => {
          if (u.type === 'badge') return <span className="ev2-tn__badge" key={i}>{u.text}</span>;
          if (u.type === 'avatar') return <span className="ev2-tn__avatar" key={i} title={u.text}>{u.initials}</span>;
          return (
            <button className="ev2-tn__btn" key={i} onClick={u.onClick}>
              {u.text}
              {u.badge && <span className="ev2-tn__badge">{u.badge}</span>}
            </button>
          );
        })}
      </div>
    </header>
  );
}
