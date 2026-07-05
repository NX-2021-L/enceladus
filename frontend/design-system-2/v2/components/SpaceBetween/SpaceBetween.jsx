// Enceladus v2 · SpaceBetween — Cloudscape SpaceBetween layout utility.
const EV2_SPACE_SIZES = { xxxs: 2, xxs: 4, xs: 8, s: 12, m: 16, l: 20, xl: 24, xxl: 32 };

export function SpaceBetween({ direction = 'vertical', size = 'm', alignItems, children }) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: direction === 'horizontal' ? 'row' : 'column',
      gap: EV2_SPACE_SIZES[size] ?? 16,
      alignItems: alignItems || (direction === 'horizontal' ? 'center' : undefined),
      flexWrap: direction === 'horizontal' ? 'wrap' : undefined,
    }}>
      {children}
    </div>
  );
}
