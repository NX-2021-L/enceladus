// Enceladus v2 · LiveRegion — Cloudscape LiveRegion (a11y announcer), deep re-brand.
export function LiveRegion({ children, assertive = false, visible = false }) {
  const style = visible ? {
    fontFamily: 'var(--font-mono,monospace)', fontSize: 12, color: 'var(--enc-dust,#6B8A94)',
  } : {
    position: 'absolute', width: 1, height: 1, padding: 0, margin: -1,
    overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap', border: 0,
  };
  return <div aria-live={assertive ? 'assertive' : 'polite'} aria-atomic="true" style={style}>{children}</div>;
}
