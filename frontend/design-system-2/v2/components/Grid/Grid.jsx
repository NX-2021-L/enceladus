// Enceladus v2 · Grid — Cloudscape Grid, deep re-brand (12-col).
export function Grid({ gridDefinition = [], children }) {
  const kids = React.Children.toArray(children);
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: 16, fontFamily: "var(--font-body,'Inter',sans-serif)" }}>
      {kids.map((child, i) => {
        const def = gridDefinition[i] || {};
        const span = def.colspan || 12;
        const offset = def.offset || 0;
        return (
          <div key={i} style={{ gridColumn: `${offset + 1} / span ${span}` }}>{child}</div>
        );
      })}
    </div>
  );
}
