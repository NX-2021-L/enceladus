// Enceladus v2 · Pagination — Cloudscape Pagination, deep re-brand.
const ev2PagCss = `
.ev2-pag{display:inline-flex;align-items:center;gap:2px;font-family:var(--font-mono,monospace)}
.ev2-pag__btn{min-width:28px;height:28px;padding:0 6px;border:1px solid transparent;background:none;border-radius:5px;color:var(--enc-dust,#6B8A94);font-family:var(--font-mono,monospace);font-size:13px;cursor:pointer;transition:all var(--dur-fast,150ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1));display:inline-flex;align-items:center;justify-content:center}
.ev2-pag__btn:hover:not(:disabled){color:var(--enc-teal-light,#7AC8D4);background:rgba(61,155,168,.1)}
.ev2-pag__btn--active{background:var(--enc-teal,#3D9BA8);color:var(--enc-void,#0A0A0F)}
.ev2-pag__btn:disabled{opacity:.35;cursor:not-allowed}
.ev2-pag__ellipsis{color:var(--enc-dust,#6B8A94);padding:0 4px;font-size:13px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-pag-css')){const s=document.createElement('style');s.id='ev2-pag-css';s.textContent=ev2PagCss;document.head.appendChild(s);}})();

function ev2PageRange(current, total) {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  if (current <= 4) return [1, 2, 3, 4, 5, '…', total];
  if (current >= total - 3) return [1, '…', total - 4, total - 3, total - 2, total - 1, total];
  return [1, '…', current - 1, current, current + 1, '…', total];
}

export function Pagination({ currentPageIndex = 1, pagesCount = 1, disabled = false, onChange }) {
  const go = (p) => { if (p >= 1 && p <= pagesCount && p !== currentPageIndex) onChange && onChange({ detail: { currentPageIndex: p } }); };
  const arrow = (d) => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points={d === 'prev' ? '15 18 9 12 15 6' : '9 18 15 12 9 6'} />
    </svg>
  );
  return (
    <div className="ev2-pag" role="navigation" aria-label="Pagination">
      <button className="ev2-pag__btn" disabled={disabled || currentPageIndex === 1} onClick={() => go(currentPageIndex - 1)} aria-label="Previous page">{arrow('prev')}</button>
      {ev2PageRange(currentPageIndex, pagesCount).map((p, i) => p === '…'
        ? <span className="ev2-pag__ellipsis" key={`e${i}`}>…</span>
        : <button key={p} className={`ev2-pag__btn${p === currentPageIndex ? ' ev2-pag__btn--active' : ''}`} disabled={disabled} onClick={() => go(p)} aria-current={p === currentPageIndex}>{p}</button>)}
      <button className="ev2-pag__btn" disabled={disabled || currentPageIndex === pagesCount} onClick={() => go(currentPageIndex + 1)} aria-label="Next page">{arrow('next')}</button>
    </div>
  );
}
