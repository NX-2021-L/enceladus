// Enceladus v2 · FileUpload — Cloudscape FileUpload, deep re-brand.
const ev2FileCss = `
.ev2-file{font-family:var(--font-body,'Inter',sans-serif)}
.ev2-file__drop{display:flex;align-items:center;gap:12px;padding:16px;border:1px dashed var(--v2-field-border,rgba(61,155,168,.35));border-radius:var(--v2-panel-radius,8px);background:var(--v2-field-bg,#0D1220);transition:border-color var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),background var(--dur-base,200ms) var(--ease-orbit);cursor:pointer}
.ev2-file__drop:hover,.ev2-file--drag .ev2-file__drop{border-color:var(--enc-teal,#3D9BA8);background:rgba(61,155,168,.06)}
.ev2-file__icon{color:var(--enc-teal,#3D9BA8);flex:0 0 auto}
.ev2-file__prompt{font-size:14px;color:var(--enc-starlight,#EEF2F7)}
.ev2-file__prompt b{color:var(--enc-teal-light,#7AC8D4);font-weight:600}
.ev2-file__hint{font-size:12px;color:var(--enc-dust,#6B8A94);margin-top:2px}
.ev2-file__list{margin-top:10px;display:flex;flex-direction:column;gap:6px}
.ev2-file__item{display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--enc-surface,#111827);border:1px solid var(--v2-panel-border,rgba(61,155,168,.2));border-radius:6px}
.ev2-file__name{font-size:13px;color:var(--enc-starlight,#EEF2F7);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev2-file__size{font-family:var(--font-mono,monospace);font-size:11px;color:var(--enc-dust,#6B8A94)}
.ev2-file__x{appearance:none;border:none;background:none;color:var(--enc-dust,#6B8A94);cursor:pointer;font-size:14px;padding:2px 4px}
.ev2-file__x:hover{color:var(--enc-crimson,#C85060)}
.ev2-file input{display:none}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-file-css')){const s=document.createElement('style');s.id='ev2-file-css';s.textContent=ev2FileCss;document.head.appendChild(s);}})();

export function FileUpload({ value = [], multiple = false, constraintText, accept, onChange }) {
  const [drag, setDrag] = React.useState(false);
  const inputRef = React.useRef(null);
  const emit = (files) => onChange && onChange({ detail: { value: files } });
  const onFiles = (list) => {
    const arr = Array.from(list).map((f) => ({ name: f.name, size: f.size }));
    emit(multiple ? [...value, ...arr] : arr.slice(0, 1));
  };
  return (
    <div className={`ev2-file${drag ? ' ev2-file--drag' : ''}`}>
      <div className="ev2-file__drop" role="button" tabIndex={0}
        onClick={() => inputRef.current && inputRef.current.click()}
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); onFiles(e.dataTransfer.files); }}>
        <span className="ev2-file__icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
        </span>
        <div>
          <div className="ev2-file__prompt"><b>Choose file{multiple ? 's' : ''}</b> or drag & drop</div>
          {constraintText && <div className="ev2-file__hint">{constraintText}</div>}
        </div>
        <input ref={inputRef} type="file" multiple={multiple} accept={accept} onChange={(e) => onFiles(e.target.files)} />
      </div>
      {value.length > 0 && (
        <div className="ev2-file__list">
          {value.map((f, i) => (
            <div className="ev2-file__item" key={i}>
              <span className="ev2-file__name">{f.name}</span>
              <span className="ev2-file__size">{(f.size / 1024).toFixed(1)} KB</span>
              <button className="ev2-file__x" aria-label={`Remove ${f.name}`}
                onClick={() => emit(value.filter((_, j) => j !== i))}>✕</button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
