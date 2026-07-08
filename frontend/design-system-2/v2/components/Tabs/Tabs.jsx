// Enceladus v2 · Tabs — Cloudscape Tabs, deep re-brand.
const ev2TabsCss = `
.ev2-tabs{font-family:var(--font-body,'Inter',sans-serif);max-width:100%}
.ev2-tabs__bar{display:flex;gap:2px;border-bottom:1px solid var(--v2-divider,rgba(61,155,168,.12));overflow-x:auto;max-width:100%}
.ev2-tab{appearance:none;border:none;background:none;padding:9px 16px;font-family:var(--font-heading,'Space Grotesk',sans-serif);font-weight:500;font-size:14px;color:var(--enc-dust,#6B8A94);cursor:pointer;position:relative;white-space:nowrap;transition:color var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1))}
.ev2-tab:hover:not(.ev2-tab--active):not(:disabled){color:var(--enc-teal-light,#7AC8D4)}
.ev2-tab--active{color:var(--enc-seafoam,#C8DDD9)}
.ev2-tab--active::after{content:'';position:absolute;left:8px;right:8px;bottom:-1px;height:2px;background:var(--enc-teal,#3D9BA8);border-radius:1px}
.ev2-tab:disabled{opacity:.4;cursor:not-allowed}
.ev2-tab--zero:not(.ev2-tab--active){opacity:.55}
.ev2-tab__count{margin-left:6px;font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-dust,#6B8A94)}
.ev2-tabs__panel{padding:16px 4px;font-size:14px;line-height:1.6;color:var(--enc-starlight,#EEF2F7)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-tabs-css')){const s=document.createElement('style');s.id='ev2-tabs-css';s.textContent=ev2TabsCss;document.head.appendChild(s);}})();

export function Tabs({ tabs = [], activeTabId, onChange }) {
  const [internal, setInternal] = React.useState(activeTabId || (tabs[0] && tabs[0].id));
  const active = activeTabId !== undefined ? activeTabId : internal;
  const select = (id) => { if (activeTabId === undefined) setInternal(id); onChange && onChange({ detail: { activeTabId: id } }); };
  const activeTab = tabs.find((t) => t.id === active);
  return (
    <div className="ev2-tabs">
      <div className="ev2-tabs__bar" role="tablist">
        {tabs.map((t) => (
          <button key={t.id} role="tab" aria-selected={t.id === active} disabled={t.disabled}
            className={`ev2-tab${t.id === active ? ' ev2-tab--active' : ''}${t.count === 0 ? ' ev2-tab--zero' : ''}`} onClick={() => select(t.id)}>
            {t.label}
            {typeof t.count === 'number' && t.count > 0 && <span className="ev2-tab__count">{t.count}</span>}
          </button>
        ))}
      </div>
      <div className="ev2-tabs__panel" role="tabpanel">{activeTab && activeTab.content}</div>
    </div>
  );
}
