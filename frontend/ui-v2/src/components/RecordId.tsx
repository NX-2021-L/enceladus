import './copyIdButton.css'
/** Record ID rendered as telemetry-decoration: JetBrains Mono, teal, per the
 *  design contract (Law 5 — "telemetry is decoration"). */
export function RecordId({ id }: { id: string }) {
  return (
    <span className="enc-record-id enc-id">
      {id}
    </span>
  )
}
