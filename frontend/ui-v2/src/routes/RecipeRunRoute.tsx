import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useParams, useSearch } from '@tanstack/react-router'
import { GateForm, RecipeRunView, useRun } from '@io-kit/recipes/react'
import { isDryRunPlan } from '@io-kit/recipes'
import type { DryRunPlan, RecipeRun } from '@io-kit/recipes'
import { PageHeader } from '../components/PageHeader'
import { Header } from '../design-system'
import { createRecipeClient, createRecipeGateSource, newIdempotencyKey, RUN_POLL_MS } from '../api/recipes'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { RecipePlanView } from './RecipePlanView'
import { ACTIVE_RUN_STATUSES, errMsg, parseRecipesSearch, versionOf } from './recipesView'
import './recipes.css'

/** The gate a run opened is a hub escalation: deep link to the escalations surface, decide in GateForm. */
function GateSection({ run, project, onDecided }: { run: RecipeRun; project: string; onDecided: () => void }) {
  const gate = run.gate
  const source = createRecipeGateSource()
  const card = useQuery({
    queryKey: ['recipes', 'gate', project, gate?.escalation_id],
    enabled: gate !== null,
    queryFn: () => source.get(gate?.escalation_id ?? '', { project: run.project_id || project }),
  })
  if (!gate) return null
  return (
    <section className="ev2-recipes__panel" aria-label="Open gate">
      <Header variant="h2">Open gate: {gate.step_id}</Header>
      <p>
        This gate is escalation <Link to="/escalations" search={{ focus: gate.escalation_id } as never} className="ev2-recipes__link" data-testid="gate-deeplink">{gate.escalation_id}</Link>
        {' '}(expires {gate.expires_at}). Decide it below or on the escalations surface, then resume.
      </p>
      {card.isPending ? <p role="status">Loading gate...</p> : null}
      {card.isError ? <p role="alert">Could not load the gate card: {errMsg(card.error)}</p> : null}
      {card.data ? <GateForm card={card.data} source={source} onDecided={onDecided} /> : null}
    </section>
  )
}

/** /recipes/runs/:runId: RecipeRunView, live updates (subscribeRun poll), Resume, Cancel, Dry run all. */
export function RecipeRunRoute() {
  const { runId = '' } = useParams({ strict: false }) as { runId?: string }
  const { project } = parseRecipesSearch(useSearch({ strict: false }) as Record<string, unknown>)
  useDocumentTitle(runId || 'Recipe run')
  const client = createRecipeClient(project)
  const { run, error, loading, refresh, resume, cancel } = useRun(client, runId, { intervalMs: RUN_POLL_MS })
  const recipeId = run?.recipe_ref.recipe_id
  const def = useQuery({
    queryKey: ['recipes', 'get', project, recipeId, run?.recipe_ref.version],
    enabled: recipeId !== undefined,
    queryFn: () => client.recipes.get({ recipeId: recipeId ?? '', version: run?.recipe_ref.version }),
  })
  const [actionError, setActionError] = useState<string | undefined>()
  const [plan, setPlan] = useState<DryRunPlan | undefined>()
  const recipeDefinition = versionOf(def.data)?.definition

  if (loading && !run) return <div className="ev2-recipes"><PageHeader title={runId} /><p role="status">Loading run...</p></div>
  if (!run) return <div className="ev2-recipes"><PageHeader title={runId} /><p role="alert">{error ? `Failed to load run: ${errMsg(error)}` : 'Run not found.'}</p></div>

  const active = ACTIVE_RUN_STATUSES.includes(run.status)
  async function doResume() {
    setActionError(undefined)
    try {
      await resume({ resumeToken: run?.resume_token ?? '' })
    } catch (e) {
      setActionError(errMsg(e))
    }
  }
  async function doDryRun() {
    if (!run) return
    setActionError(undefined)
    try {
      const out = await client.startRun({
        recipeId: run.recipe_ref.recipe_id,
        version: run.recipe_ref.version,
        inputs: run.inputs,
        mode: 'dry_run',
        idempotencyKey: newIdempotencyKey(),
        ...(recipeDefinition ? { definition: recipeDefinition } : {}),
      })
      if (isDryRunPlan(out)) setPlan(out)
    } catch (e) {
      setActionError(errMsg(e))
    }
  }
  return (
    <div className="ev2-recipes">
      <PageHeader
        title={`Run ${run.run_id}`}
        description={<>
          <span className="ev2-recipes__state" data-state={run.status}>{run.status}</span> - {run.recipe_ref.recipe_id} {run.recipe_ref.version}
          {active ? ` - live, refreshing every ${RUN_POLL_MS / 1000}s` : ''}
        </>}
        actions={<Link to="/recipes/$recipeId" params={{ recipeId: run.recipe_ref.recipe_id }} search={{ project }} className="ev2-recipes__link">Recipe</Link>}
      />
      <RecipeRunView run={run} definition={recipeDefinition} onCancel={active ? () => void cancel('cancelled from the recipes UI') : undefined}>
        {run.status === 'awaiting_gate' ? <GateSection run={run} project={project} onDecided={() => void refresh()} /> : null}
      </RecipeRunView>
      <div className="ev2-recipes__actions">
        <button type="button" onClick={() => void doDryRun()}>Dry run all</button>
        {run.status === 'awaiting_gate' ? <button type="button" disabled={!run.resume_token} onClick={() => void doResume()}>Resume</button> : null}
      </div>
      {error ? <p role="alert">{errMsg(error)}</p> : null}
      {actionError ? <p role="alert">{actionError}</p> : null}
      {plan ? <RecipePlanView plan={plan} /> : null}
    </div>
  )
}
