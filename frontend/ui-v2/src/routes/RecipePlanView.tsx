import type { DryRunPlan } from '@io-kit/recipes'
import { Header } from '../design-system'
import { planHasUnresolved } from './recipesView'

/** The dry-run result: planned calls with zero writes; $unresolved marks values minted or produced at run time. */
export function RecipePlanView({ plan }: { plan: DryRunPlan }) {
  return (
    <section className="ev2-recipes__panel" aria-label="Dry run plan">
      <Header variant="h2" counter={`(${plan.planned.length})`}>Dry run plan</Header>
      <p role="status" className="ev2-recipes__note">
        Dry run: zero writes were made.{' '}
        {plan.unresolved || planHasUnresolved(plan.planned) ? 'Values shown as $unresolved are minted or produced by earlier steps at run time. ' : ''}
        {plan.fixture_mode ? 'Fixture mode: no live calls.' : ''}
      </p>
      <ol className="ev2-recipes__plan">
        {plan.planned.map((call, i) => (
          <li key={i} data-unresolved={planHasUnresolved(call) ? 'true' : 'false'}>
            <code>{String(call.step_id ?? call.id ?? `step ${i + 1}`)}</code> <span>{String(call.action ?? '')}</span>
            <pre className="ev2-recipes__pre">{JSON.stringify(call, null, 2)}</pre>
          </li>
        ))}
      </ol>
    </section>
  )
}
