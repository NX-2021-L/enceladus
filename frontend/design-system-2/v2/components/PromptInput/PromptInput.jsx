// Enceladus v2 · PromptInput — Cloudscape PromptInput, deep re-brand (agent console).
const ev2PromptCss = `
.ev2-prompt{display:flex;align-items:flex-end;gap:8px;padding:8px 8px 8px 14px;background:var(--v2-field-bg,#0D1220);border:1px solid var(--v2-field-border,rgba(61,155,168,.25));border-radius:var(--v2-panel-radius,8px);transition:border-color var(--dur-base,200ms) var(--ease-orbit,cubic-bezier(.4,0,.2,1)),box-shadow var(--dur-base,200ms) var(--ease-orbit)}
.ev2-prompt--focused{border-color:var(--v2-field-border-focus,#3D9BA8);box-shadow:var(--v2-focus-ring)}
.ev2-prompt__ta{flex:1;min-width:0;background:none;border:none;outline:none;resize:none;color:var(--enc-starlight,#EEF2F7);font-family:var(--font-body,'Inter',sans-serif);font-size:14px;line-height:1.5;max-height:140px;padding:5px 0}
.ev2-prompt__ta::placeholder{color:var(--v2-field-placeholder,#4A5E68)}
.ev2-prompt__send{flex:0 0 auto;width:30px;height:30px;border-radius:6px;border:none;background:var(--enc-teal,#3D9BA8);color:var(--enc-void,#0A0A0F);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:background var(--dur-fast,150ms) var(--ease-orbit)}
.ev2-prompt__send:hover:not(:disabled){background:var(--enc-teal-light,#7AC8D4)}
.ev2-prompt__send:disabled{opacity:.35;cursor:not-allowed}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-prompt-css')){const s=document.createElement('style');s.id='ev2-prompt-css';s.textContent=ev2PromptCss;document.head.appendChild(s);}})();

export function PromptInput({ value = '', placeholder = 'Ask the coordination agent…', disabled = false, onChange, onAction }) {
  const [focused, setFocused] = React.useState(false);
  return (
    <div className={`ev2-prompt${focused ? ' ev2-prompt--focused' : ''}`}>
      <textarea className="ev2-prompt__ta" rows={1} value={value} placeholder={placeholder} disabled={disabled}
        onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}
        onChange={(e) => onChange && onChange({ detail: { value: e.target.value } })}
        onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onAction && onAction({ detail: { value } }); } }} />
      <button className="ev2-prompt__send" aria-label="Send" disabled={disabled || !value.trim()}
        onClick={() => onAction && onAction({ detail: { value } })}>
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
      </button>
    </div>
  );
}
