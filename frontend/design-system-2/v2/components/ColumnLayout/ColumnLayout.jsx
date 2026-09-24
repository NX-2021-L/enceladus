// Enceladus v2 · ColumnLayout — Cloudscape ColumnLayout, deep re-brand.
const ev2ColCss = `
.ev2-collayout{display:grid;gap:16px;font-family:var(--font-body,'Inter',sans-serif)}
.ev2-collayout--bordered>*{position:relative}
.ev2-collayout--bordered.ev2-collayout--divh{gap:0}
.ev2-collayout--divh>*{padding:2px 20px}
.ev2-collayout--divh>*:not(:last-child){border-right:1px solid var(--v2-divider,rgba(61,155,168,.12))}
.ev2-collayout--divh>*:first-child{padding-left:0}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-col-css')){const s=document.createElement('style');s.id='ev2-col-css';s.textContent=ev2ColCss;document.head.appendChild(s);}})();

export function ColumnLayout({ columns = 2, borders = 'none', children }) {
  const cls = ['ev2-collayout',
    borders !== 'none' ? 'ev2-collayout--bordered' : '',
    borders === 'vertical' ? 'ev2-collayout--divh' : ''].filter(Boolean).join(' ');
  return <div className={cls} style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>{children}</div>;
}
