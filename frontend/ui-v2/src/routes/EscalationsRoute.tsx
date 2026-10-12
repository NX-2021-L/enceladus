/**
 * Escalations -- io's approval cockpit (ENC-TSK-O40 / ENC-FTR-121 Ph3), restored by DVP-TSK-A20.
 *
 * DVP-TSK-970 made /escalations the ONE all-projects inbox on @io-kit/gates; DVP-TSK-981 removed
 * the pre-kit page with its per-project fan-out and ESC-only reader. io asked for the cockpit look
 * and feel back (2026-10-12), so the original presentation (PageHeader, pending/terminal tabs,
 * StackedTable rows, modal decide flow) is the default again, rendered on the hub data and the kit
 * decide path: see EscalationsCockpit.tsx / escalationCockpit.ts.
 */
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { EscalationsCockpit } from './EscalationsCockpit'

export function EscalationsRoute() {
  useDocumentTitle('Escalations')
  return (
    <div className="ev2-page">
      <EscalationsCockpit />
    </div>
  )
}
