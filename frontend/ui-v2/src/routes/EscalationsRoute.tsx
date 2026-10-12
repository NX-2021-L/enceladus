/**
 * Escalations -- io's approval cockpit (ENC-TSK-O40 / ENC-FTR-121 Ph3).
 *
 * DVP-TSK-970: /escalations is the ONE all-projects inbox (ruling F-04). It renders the
 * @io-kit/gates inbox (GateInboxPanel). DVP-TSK-981 removed the pre-kit decide page that stayed
 * reachable behind ?escalations=legacy for one release, with its ESC-only pending/terminal split,
 * per-project fan-out (ENC-ISS-773 is now closed by the all-projects project_id=* read) and the
 * read-time expiry backfill. Decisions are made on the kit card, bound to the card's version and
 * recorded as a receipt; the backend three-gate fail-close (ENC-ISS-501) is unchanged.
 */
import { PageHeader } from '../components/PageHeader'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { GateInboxPanel } from './GateInboxPanel'

export function EscalationsRoute() {
  useDocumentTitle('Escalations')
  return (
    <div className="ev2-page">
      <PageHeader title="Escalations" description="Every gate from every project that needs a human verdict. Clear or reject with the exact call shown; each verdict is bound to the card's version and recorded as a receipt." />
      <GateInboxPanel />
    </div>
  )
}
