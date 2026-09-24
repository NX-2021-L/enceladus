// Enceladus v2 · Container — Cloudscape Container, deep re-brand.
const ev2ContainerCss = `
.ev2-container{background:var(--enc-surface,#111827);border:1px solid var(--v2-panel-border,rgba(61,155,168,.2));border-radius:var(--v2-panel-radius,8px);transition:border-color var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1));overflow:hidden}
.ev2-container:hover{border-color:rgba(61,155,168,.4)}
.ev2-container__header{padding:16px 20px 0}
.ev2-container__content{padding:16px 20px 20px;font-family:var(--font-body,'Inter',sans-serif);font-size:14px;line-height:1.6;color:var(--enc-starlight,#EEF2F7)}
.ev2-container__footer{padding:12px 20px;border-top:1px solid var(--v2-divider,rgba(61,155,168,.12));font-size:13px;color:var(--enc-dust,#6B8A94)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-container-css')){const s=document.createElement('style');s.id='ev2-container-css';s.textContent=ev2ContainerCss;document.head.appendChild(s);}})();

export function Container({ header, footer, children }) {
  return (
    <div className="ev2-container">
      {header && <div className="ev2-container__header">{header}</div>}
      <div className="ev2-container__content">{children}</div>
      {footer && <div className="ev2-container__footer">{footer}</div>}
    </div>
  );
}
