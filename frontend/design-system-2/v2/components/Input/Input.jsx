// Enceladus v2 · Input — Cloudscape Input, deep re-brand.
const ev2InputCss = `
.ev2-input{display:inline-flex;align-items:center;gap:8px;width:100%;height:var(--v2-control-height,32px);padding:0 12px;background:var(--v2-field-bg,#0D1220);border:1px solid var(--v2-field-border,rgba(61,155,168,.25));border-radius:var(--v2-control-radius,6px);transition:border-color var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),box-shadow var(--dur-base,200ms) var(--ease-orbit)}
.ev2-input:hover{border-color:var(--v2-field-border-hover,rgba(61,155,168,.45))}
.ev2-input--focused{border-color:var(--v2-field-border-focus,#3D9BA8);box-shadow:var(--v2-focus-ring)}
.ev2-input--invalid{border-color:var(--enc-crimson,#C85060)}
.ev2-input--invalid.ev2-input--focused{box-shadow:0 0 0 2px rgba(200,80,96,.35)}
.ev2-input--disabled{opacity:.45;cursor:not-allowed}
.ev2-input__field{flex:1;min-width:0;background:none;border:none;outline:none;color:var(--enc-starlight,#EEF2F7);font-family:var(--font-body,'Inter',sans-serif);font-size:14px;line-height:1}
.ev2-input__field::placeholder{color:var(--v2-field-placeholder,#4A5E68)}
.ev2-input__field:disabled{cursor:not-allowed}
.ev2-input--mono .ev2-input__field{font-family:var(--font-mono,monospace);letter-spacing:.02em}
.ev2-input__icon{color:var(--enc-dust,#6B8A94);flex:0 0 auto;display:flex}
.ev2-input__icon svg{width:15px;height:15px}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-input-css')){const s=document.createElement('style');s.id='ev2-input-css';s.textContent=ev2InputCss;document.head.appendChild(s);}})();

export function Input({ value = '', placeholder, type = 'text', disabled = false, invalid = false, mono = false, icon, onChange, ariaLabel }) {
  const [focused, setFocused] = React.useState(false);
  const cls = [
    'ev2-input',
    focused ? 'ev2-input--focused' : '',
    invalid ? 'ev2-input--invalid' : '',
    disabled ? 'ev2-input--disabled' : '',
    mono ? 'ev2-input--mono' : '',
  ].filter(Boolean).join(' ');
  return (
    <div className={cls}>
      {icon && <span className="ev2-input__icon">{icon}</span>}
      <input
        className="ev2-input__field"
        type={type}
        value={value}
        placeholder={placeholder}
        disabled={disabled}
        aria-label={ariaLabel}
        aria-invalid={invalid || undefined}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        onChange={(e) => onChange && onChange({ detail: { value: e.target.value } })}
      />
    </div>
  );
}
