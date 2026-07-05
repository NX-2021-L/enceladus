// Enceladus v2 · Link — Cloudscape Link, deep re-brand.
const ev2LinkCss = `
.ev2-link{color:var(--enc-teal-light,#7AC8D4);text-decoration:none;cursor:pointer;transition:color var(--dur-fast,150ms) var(--ease-orbit);border-bottom:1px solid rgba(122,200,212,.35);font-family:inherit}
.ev2-link:hover{color:var(--enc-seafoam,#C8DDD9);border-bottom-color:currentColor}
.ev2-link:focus-visible{outline:none;box-shadow:var(--v2-focus-ring);border-radius:2px}
.ev2-link--secondary{color:var(--enc-dust,#6B8A94);border-bottom-color:rgba(107,138,148,.35)}
.ev2-link--secondary:hover{color:var(--enc-teal-light,#7AC8D4)}
.ev2-link--record{font-family:var(--font-mono,monospace);font-size:.95em;color:var(--enc-teal,#3D9BA8);border-bottom:none}
.ev2-link--record:hover{color:var(--enc-teal-light,#7AC8D4);text-decoration:underline}
.ev2-link__ext{font-size:.8em;margin-left:3px;opacity:.7}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-link-css')){const s=document.createElement('style');s.id='ev2-link-css';s.textContent=ev2LinkCss;document.head.appendChild(s);}})();

export function Link({ href = '#', variant = 'primary', external = false, onFollow, children }) {
  const cls = `ev2-link${variant !== 'primary' ? ` ev2-link--${variant}` : ''}`;
  return (
    <a className={cls} href={href} target={external ? '_blank' : undefined} rel={external ? 'noopener noreferrer' : undefined}
      onClick={onFollow ? (e) => { e.preventDefault(); onFollow(e); } : undefined}>
      {children}
      {external && <span className="ev2-link__ext" aria-label="opens in new tab">↗</span>}
    </a>
  );
}
