// Enceladus v2 · Autosuggest — Cloudscape Autosuggest, deep re-brand.
const ev2AutoCss = `
.ev2-auto{position:relative;font-family:var(--font-body,'Inter',sans-serif);width:100%}
.ev2-auto__menu{position:absolute;top:calc(100% + 4px);left:0;right:0;z-index:20;background:var(--enc-surface,#111827);border:1px solid var(--v2-panel-border,rgba(61,155,168,.25));border-radius:var(--v2-panel-radius,8px);box-shadow:var(--v2-dropdown-shadow,0 8px 32px rgba(0,0,0,.6));padding:4px;max-height:220px;overflow-y:auto}
.ev2-auto__opt{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:7px 10px;border-radius:4px;cursor:pointer;font-size:14px;color:var(--enc-starlight,#EEF2F7);transition:background var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-auto__opt:hover{background:rgba(61,155,168,.1)}
.ev2-auto__opt--active,.ev2-auto__opt--active:hover{background:rgba(61,155,168,.22);box-shadow:inset 0 0 0 1px rgba(61,155,168,.55)}
.ev2-auto__opt mark{background:none;color:var(--enc-teal-light,#7AC8D4);font-weight:600}
.ev2-auto__tag{font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-dust,#6B8A94)}
.ev2-auto__empty{padding:9px 10px;font-size:13px;color:var(--enc-dust,#6B8A94)}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-auto-css')){const s=document.createElement('style');s.id='ev2-auto-css';s.textContent=ev2AutoCss;document.head.appendChild(s);}else if(typeof document!=='undefined'){const s=document.getElementById('ev2-auto-css');if(s&&s.textContent!==ev2AutoCss)s.textContent=ev2AutoCss;}})();

function ev2Highlight(text, q) {
  if (!q) return text;
  const i = String(text).toLowerCase().indexOf(q.toLowerCase());
  if (i < 0) return text;
  const t = String(text);
  return [t.slice(0, i), React.createElement('mark', { key: 'm' }, t.slice(i, i + q.length)), t.slice(i + q.length)];
}

/**
 * Keyboard contract (ENC-TSK-P57, W3C APG combobox pattern):
 *  - ArrowDown/ArrowUp open the list when closed and move the active option
 *    when open, wrapping past either end. Default is always prevented while
 *    the list is open (or being opened) so the page never scrolls underneath.
 *  - Enter with an active option selects it and prevents default (no form
 *    submit); Enter with the list closed — or open with nothing active —
 *    falls through so an enclosing form/search still runs.
 *  - Escape closes the list without clearing the typed text.
 *  - Tab closes the list and lets focus move on naturally.
 * DOM focus stays on the input; the active option is conveyed via
 * aria-activedescendant. Hover deliberately does NOT move the active option,
 * so an incidental mouse move never overrides a keyboard selection.
 */
export function Autosuggest({ value = '', options = [], placeholder, onChange, emptyText = 'No matches', ariaLabel }) {
  const NS = (typeof window !== 'undefined' && window.EnceladusDesignSystem_7eb1fe) || {};
  const InputCmp = NS.Input;
  const [open, setOpen] = React.useState(false);
  const [activeIndex, setActiveIndex] = React.useState(-1);
  const ref = React.useRef(null);
  const listRef = React.useRef(null);
  const reactId = React.useId();
  const listboxId = `ev2-auto-list-${reactId.replace(/:/g, '')}`;
  React.useEffect(() => {
    if (!open) return;
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) { setOpen(false); setActiveIndex(-1); } };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);
  const filtered = options.filter((o) => String(o.value).toLowerCase().includes(value.toLowerCase()));
  React.useEffect(() => {
    if (activeIndex < 0 || !listRef.current) return;
    const el = listRef.current.querySelector('.ev2-auto__opt--active');
    if (el && typeof el.scrollIntoView === 'function') el.scrollIntoView({ block: 'nearest' });
  }, [activeIndex]);
  const handle = (v) => { onChange && onChange({ detail: { value: v } }); setOpen(true); setActiveIndex(-1); };
  const select = (v) => { onChange && onChange({ detail: { value: v } }); setOpen(false); setActiveIndex(-1); };
  const activeOptionId = open && activeIndex >= 0 && activeIndex < filtered.length ? `${listboxId}-opt-${activeIndex}` : undefined;
  const handleKeyDown = (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      if (!open && filtered.length === 0) return;
      e.preventDefault();
      if (filtered.length === 0) return;
      if (!open) {
        setOpen(true);
        setActiveIndex(e.key === 'ArrowDown' ? 0 : filtered.length - 1);
        return;
      }
      setActiveIndex((i) => {
        if (e.key === 'ArrowDown') return i >= filtered.length - 1 ? 0 : i + 1;
        return i <= 0 ? filtered.length - 1 : i - 1;
      });
      return;
    }
    if (e.key === 'Enter') {
      if (open && activeIndex >= 0 && activeIndex < filtered.length) {
        e.preventDefault();
        select(String(filtered[activeIndex].value));
      } else if (open) {
        setOpen(false);
        setActiveIndex(-1);
      }
      return;
    }
    if (e.key === 'Escape') {
      if (open) {
        e.preventDefault();
        e.stopPropagation();
        setOpen(false);
        setActiveIndex(-1);
      }
      return;
    }
    if (e.key === 'Tab') {
      if (open) { setOpen(false); setActiveIndex(-1); }
    }
  };
  const comboAria = {
    role: 'combobox',
    'aria-expanded': open,
    'aria-controls': open ? listboxId : undefined,
    'aria-autocomplete': 'list',
    'aria-activedescendant': activeOptionId,
  };
  return (
    <div className="ev2-auto" ref={ref} onKeyDown={handleKeyDown}>
      {InputCmp
        ? <InputCmp value={value} placeholder={placeholder} ariaLabel={ariaLabel} combobox={comboAria} onChange={(ev) => handle(ev.detail.value)} />
        : <input value={value} placeholder={placeholder} aria-label={ariaLabel} {...comboAria} onChange={(ev) => handle(ev.target.value)}
            style={{ width: '100%', height: 32, padding: '0 12px', background: '#0D1220', border: '1px solid rgba(61,155,168,.25)', borderRadius: 6, color: '#EEF2F7', fontSize: 14, boxSizing: 'border-box' }} />}
      {open && (
        <div className="ev2-auto__menu" role="listbox" id={listboxId} ref={listRef}>
          {filtered.length === 0 && <div className="ev2-auto__empty">{emptyText}</div>}
          {filtered.map((opt, idx) => (
            <div key={opt.value} role="option" id={`${listboxId}-opt-${idx}`} aria-selected={idx === activeIndex}
              className={`ev2-auto__opt${idx === activeIndex ? ' ev2-auto__opt--active' : ''}`}
              onMouseDown={() => select(String(opt.value))}>
              <span>{ev2Highlight(opt.value, value)}{opt.description && <span className="ev2-auto__tag" style={{ marginLeft: 8 }}>{opt.description}</span>}</span>
              {opt.tag && <span className="ev2-auto__tag">{opt.tag}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
