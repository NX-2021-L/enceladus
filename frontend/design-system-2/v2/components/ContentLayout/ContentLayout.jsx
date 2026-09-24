// Enceladus v2 · ContentLayout — Cloudscape ContentLayout, deep re-brand.
const ev2ClCss = `
.ev2-contentlayout{font-family:var(--font-body,'Inter',sans-serif)}
.ev2-contentlayout__header{background:var(--enc-surface-alt,#1C2333);border-bottom:1px solid var(--v2-divider,rgba(61,155,168,.12));padding:24px 28px}
.ev2-contentlayout__body{padding:24px 28px;display:flex;flex-direction:column;gap:20px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-cl-css')){const s=document.createElement('style');s.id='ev2-cl-css';s.textContent=ev2ClCss;document.head.appendChild(s);}})();

export function ContentLayout({ header, children }) {
  return (
    <div className="ev2-contentlayout">
      {header && <div className="ev2-contentlayout__header">{header}</div>}
      <div className="ev2-contentlayout__body">{children}</div>
    </div>
  );
}
