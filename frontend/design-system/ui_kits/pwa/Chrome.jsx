// Enceladus PWA — Header + BottomNav. Copies production SVG paths verbatim.

function Header({ title, version, onMenuToggle, menuOpen, onNav, onLogout }) {
  return (
    <header className="sticky top-0 z-40 bg-slate-900/95 backdrop-blur border-b border-slate-700/50 px-4 py-3 flex items-center justify-between">
      <h1 className="text-lg font-semibold text-slate-100">{title}</h1>
      <div className="flex items-center gap-3">
        <span className="text-xs text-slate-500 font-mono">{version ? `v${version}` : '—'}</span>
        <div className="relative">
          <button onClick={onMenuToggle} aria-label="Menu" aria-expanded={menuOpen}
            className="text-slate-400 hover:text-slate-200 active:text-slate-100 transition-colors p-1 -mr-1">
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          {menuOpen && (
            <div className="absolute right-0 top-full mt-2 w-52 bg-slate-800 border border-slate-700 rounded-lg shadow-xl py-1 z-50">
              <button onClick={() => onNav('deployments')}
                className="w-full text-left px-4 py-3 text-sm text-amber-300 hover:bg-slate-700 transition-colors font-medium">
                Deployment Manager
              </button>
              <div className="border-t border-slate-700/50 my-1" />
              <button onClick={() => onNav('components')}
                className="w-full text-left px-4 py-3 text-sm text-slate-200 hover:bg-slate-700 transition-colors">
                Component Registry
              </button>
              <button onClick={() => onNav('terminal')}
                className="w-full text-left px-4 py-3 text-sm text-slate-200 hover:bg-slate-700 transition-colors">
                Terminal Sessions
              </button>
              <button onClick={() => onNav('coordination')}
                className="w-full text-left px-4 py-3 text-sm text-slate-200 hover:bg-slate-700 transition-colors">
                Coordination Monitor
              </button>
              <button onClick={() => onNav('tokens')}
                className="w-full text-left px-4 py-3 text-sm text-slate-200 hover:bg-slate-700 transition-colors">
                Access Tokens
              </button>
              <button onClick={onLogout}
                className="w-full text-left px-4 py-3 text-sm text-slate-200 hover:bg-slate-700 transition-colors">
                Log Out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

const NAV_ITEMS = [
  { key: 'home',      label: 'Home',      icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-4 0a1 1 0 01-1-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 01-1 1' },
  { key: 'projects',  label: 'Projects',  icon: 'M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10' },
  { key: 'feed',      label: 'Feed',      icon: 'M4 6h16M4 10h16M4 14h16M4 18h16' },
  { key: 'docs',      label: 'Docs',      icon: 'M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z' },
  { key: 'changelog', label: 'Changelog', icon: 'M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z' },
];

function BottomNav({ active, onNav }) {
  return (
    <nav className="fixed bottom-0 inset-x-0 z-10 bg-slate-900/95 backdrop-blur border-t border-slate-700/50">
      <div className="flex justify-around">
        {NAV_ITEMS.map(({ key, label, icon }) => {
          const isActive = active === key;
          return (
            <button key={key} onClick={() => onNav(key)}
              className={`flex flex-col items-center py-2 px-2 min-h-[44px] min-w-[40px] transition-colors ${
                isActive ? 'text-blue-400' : 'text-slate-500 hover:text-slate-300'
              }`}>
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d={icon} />
              </svg>
              <span className="text-xs mt-0.5">{label}</span>
            </button>
          );
        })}
      </div>
    </nav>
  );
}

Object.assign(window, { Header, BottomNav });
