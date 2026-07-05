// Enceladus v2 · Box — Cloudscape Box, deep re-brand. Text + spacing utility.
const ev2BoxVariants = {
  p:       { fontFamily: "var(--font-body,'Inter',sans-serif)", fontSize: 14, lineHeight: 1.6, color: 'var(--enc-starlight,#EEF2F7)' },
  small:   { fontFamily: "var(--font-body,'Inter',sans-serif)", fontSize: 12, lineHeight: 1.5, color: 'var(--enc-dust,#6B8A94)' },
  strong:  { fontFamily: "var(--font-body,'Inter',sans-serif)", fontSize: 14, fontWeight: 600, color: 'var(--enc-seafoam,#C8DDD9)' },
  label:   { fontFamily: "var(--font-body,'Inter',sans-serif)", fontSize: 11, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--enc-dust,#6B8A94)' },
  code:    { fontFamily: 'var(--font-mono,monospace)', fontSize: 13, color: 'var(--enc-teal-light,#7AC8D4)', background: 'var(--enc-slate,#2E4D5C)', padding: '2px 7px', borderRadius: 3, border: '1px solid rgba(61,155,168,.2)' },
  mono:    { fontFamily: 'var(--font-mono,monospace)', fontSize: 13, color: 'var(--enc-teal,#3D9BA8)', fontVariantNumeric: 'tabular-nums' },
  awsui:   {},
};
const EV2_COLOR_MAP = {
  'text-body-secondary': 'var(--enc-dust,#6B8A94)',
  'text-status-error': 'var(--enc-crimson,#C85060)',
  'text-status-success': 'var(--enc-teal,#3D9BA8)',
  'text-status-info': 'var(--enc-teal-light,#7AC8D4)',
  'text-status-warning': 'var(--v2-status-warning,#C9A15C)',
  'text-status-inactive': 'var(--enc-slate,#2E4D5C)',
};

export function Box({ variant = 'p', color, textAlign, margin, padding, display, children }) {
  const style = { ...(ev2BoxVariants[variant] || ev2BoxVariants.p) };
  if (color) style.color = EV2_COLOR_MAP[color] || color;
  if (textAlign) style.textAlign = textAlign;
  if (margin) style.margin = margin;
  if (padding) style.padding = padding;
  if (display) style.display = display;
  const Tag = variant === 'p' ? 'p' : 'span';
  if (Tag === 'p' && style.margin === undefined) style.margin = 0;
  return <Tag style={style}>{children}</Tag>;
}
