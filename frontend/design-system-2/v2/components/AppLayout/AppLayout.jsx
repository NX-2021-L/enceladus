// Enceladus v2 · AppLayout — Cloudscape AppLayout, deep re-brand. The cockpit shell.
const ev2AlCss = `
.ev2-al{display:flex;flex-direction:column;height:100%;background:var(--enc-void,#0A0A0F);font-family:var(--font-body,'Inter',sans-serif);overflow:hidden}
.ev2-al__top{flex:0 0 auto;z-index:5}
.ev2-al__mid{display:flex;flex:1;min-height:0}
.ev2-al__nav{flex:0 0 auto;overflow-y:auto}
.ev2-al__nav--collapsed{display:none}
.ev2-al__main{flex:1;min-width:0;display:flex;flex-direction:column;overflow:hidden}
.ev2-al__crumbs{flex:0 0 auto;padding:12px 24px 0}
.ev2-al__content{flex:1;min-width:0;overflow-y:auto;padding:16px 24px 24px;display:flex;flex-direction:column;gap:18px}
.ev2-al__tools{flex:0 0 auto;overflow-y:auto}
.ev2-al__tools--collapsed{display:none}
.ev2-al__split{flex:0 0 auto}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-al-css')){const s=document.createElement('style');s.id='ev2-al-css';s.textContent=ev2AlCss;document.head.appendChild(s);}})();

export function AppLayout({ topNavigation, navigation, navigationOpen = true, breadcrumbs, content, tools, toolsOpen = false, splitPanel }) {
  return (
    <div className="ev2-al">
      {topNavigation && <div className="ev2-al__top">{topNavigation}</div>}
      <div className="ev2-al__mid">
        {navigation && <div className={`ev2-al__nav${navigationOpen ? '' : ' ev2-al__nav--collapsed'}`}>{navigation}</div>}
        <div className="ev2-al__main">
          {breadcrumbs && <div className="ev2-al__crumbs">{breadcrumbs}</div>}
          <div className="ev2-al__content">{content}</div>
          {splitPanel && <div className="ev2-al__split">{splitPanel}</div>}
        </div>
        {tools && <div className={`ev2-al__tools${toolsOpen ? '' : ' ev2-al__tools--collapsed'}`}>{tools}</div>}
      </div>
    </div>
  );
}
