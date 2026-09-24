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
/* ENC-TSK-N46: thin search box that sits between the spacer and the
   utilities row, so Menu (the only remaining utility) stays the rightmost
   element. Narrow by default; widens on focus via :focus-within so desktop
   users get an in-place grow instead of a layout jump. AppShell decides
   (by viewport, at focus time) whether that focus also opens the full-screen
   CommandPalette overlay (mobile) or its anchored dropdown (desktop) -- this
   component only owns the input's own chrome and width transition. */
.ev2-tn__search{display:flex;align-items:center;gap:6px;flex:0 0 auto;width:9rem;padding:5px 10px;border-radius:6px;border:1px solid rgba(61,155,168,.18);background:rgba(255,255,255,.03);transition:width var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),border-color var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-tn__search:focus-within{width:16rem;border-color:rgba(61,155,168,.5)}
.ev2-tn__search-icon{flex:0 0 auto;color:var(--enc-dust,#6B8A94)}
.ev2-tn__search-input{flex:1;min-width:0;background:transparent;border:none;outline:none;color:var(--enc-starlight,#EEF2F7);font-size:13px;font-family:inherit}
.ev2-tn__search-input::placeholder{color:var(--enc-dust,#6B8A94)}
/* ENC-TSK-M75: at narrow mobile widths (<=430px) the brand + version badge +
   Menu/Search/Feed utility buttons overflowed the right edge and clipped
   "Feed" offscreen. Condense the chrome so everything stays inside the
   viewport: drop the build-version pill, collapse the wordmark to its mark
   icon only (the icon still links home), and tighten the header/utility
   spacing. Verified at 375px and 430px. */
@media (max-width:30rem){
.ev2-tn{gap:8px;padding:0 12px}
.ev2-tn__version{display:none}
.ev2-tn__title{display:none}
.ev2-tn__util{gap:2px}
.ev2-tn__btn{padding:6px 8px;font-size:12px;gap:5px}
.ev2-tn__search{width:2.25rem;padding:5px}
.ev2-tn__search:focus-within{width:9rem}
}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-tn-css')){const s=document.createElement('style');s.id='ev2-tn-css';s.textContent=ev2TnCss;document.head.appendChild(s);}})();

function SearchIcon() {
  return (
    <svg className="ev2-tn__search-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="2"/>
      <path d="M21 21l-4.35-4.35" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
    </svg>
  );
}

export function TopNavigation({ identity = {}, utilities = [], search = null }) {
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
      {search && (
        <div className="ev2-tn__search">
          <SearchIcon />
          <input
            type="search"
            className="ev2-tn__search-input"
            value={search.value ?? ''}
            onChange={search.onChange ? (e) => search.onChange(e.target.value) : undefined}
            onFocus={search.onFocus}
            onBlur={search.onBlur}
            onKeyDown={search.onKeyDown}
            placeholder={search.placeholder || 'Search'}
            aria-label={search.placeholder || 'Search'}
          />
        </div>
      )}
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
