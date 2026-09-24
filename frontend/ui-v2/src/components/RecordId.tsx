/** Record ID rendered as telemetry-decoration: JetBrains Mono, teal, per the
 *  design contract (Law 5 — "telemetry is decoration"). */
export function RecordId({ id }: { id: string }) {
  return (
    <span
      className="enc-record-id"
      style={{
        fontFamily: 'var(--font-mono)',
        color: 'var(--accent)',
        fontSize: '0.95em',
        opacity: 0.85,
        letterSpacing: '0.01em',
      }}
    >
      {id}
    </span>
  )
}
