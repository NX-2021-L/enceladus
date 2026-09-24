// Enceladus v2 · Textarea — Cloudscape Textarea, deep re-brand.
const ev2TextareaCss = `
.ev2-textarea{display:block;width:100%;min-height:76px;padding:9px 12px;background:var(--v2-field-bg,#0D1220);border:1px solid var(--v2-field-border,rgba(61,155,168,.25));border-radius:var(--v2-control-radius,6px);color:var(--enc-starlight,#EEF2F7);font-family:var(--font-body,'Inter',sans-serif);font-size:14px;line-height:1.55;resize:vertical;outline:none;transition:border-color var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),box-shadow var(--dur-base,200ms) var(--ease-orbit);box-sizing:border-box}
.ev2-textarea::placeholder{color:var(--v2-field-placeholder,#4A5E68)}
.ev2-textarea:hover{border-color:var(--v2-field-border-hover,rgba(61,155,168,.45))}
.ev2-textarea:focus{border-color:var(--v2-field-border-focus,#3D9BA8);box-shadow:var(--v2-focus-ring)}
.ev2-textarea--invalid{border-color:var(--enc-crimson,#C85060)}
.ev2-textarea--mono{font-family:var(--font-mono,monospace);font-size:13px}
.ev2-textarea:disabled{opacity:.45;cursor:not-allowed}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-textarea-css')){const s=document.createElement('style');s.id='ev2-textarea-css';s.textContent=ev2TextareaCss;document.head.appendChild(s);}})();

export function Textarea({ value = '', placeholder, rows = 3, disabled = false, invalid = false, mono = false, onChange, ariaLabel }) {
  const cls = ['ev2-textarea', invalid ? 'ev2-textarea--invalid' : '', mono ? 'ev2-textarea--mono' : ''].filter(Boolean).join(' ');
  return (
    <textarea
      className={cls}
      value={value}
      placeholder={placeholder}
      rows={rows}
      disabled={disabled}
      aria-label={ariaLabel}
      aria-invalid={invalid || undefined}
      onChange={(e) => onChange && onChange({ detail: { value: e.target.value } })}
    />
  );
}
