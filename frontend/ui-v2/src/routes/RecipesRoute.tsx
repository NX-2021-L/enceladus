import { useQueries, useQuery } from '@tanstack/react-query'
import { Link, useSearch } from '@tanstack/react-router'
import { Table } from '../components/StackedTable'
import { PageHeader } from '../components/PageHeader'
import type { TableColumnDefinition } from '../../../design-system-2/v2/components/Table/Table'
import { createRecipeClient } from '../api/recipes'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { RECIPE_PROJECTS, errMsg, parseRecipesSearch, versionOf } from './recipesView'
import './recipes.css'

interface RecipeRow {
  recipe_id: string
  name: string
  status: string
  version: string
  tools: string
  projects: string
  features: string
  project: string
}

function columns(): TableColumnDefinition<RecipeRow>[] {
  return [
    {
      id: 'name',
      header: 'Recipe',
      cell: (r) => (
        <Link to="/recipes/$recipeId" params={{ recipeId: r.recipe_id }} search={{ project: r.project }} className="ev2-recipes__link">
          {r.name || r.recipe_id}
        </Link>
      ),
    },
    { id: 'status', header: 'Lifecycle', cell: (r) => <span className="ev2-recipes__state" data-state={r.status}>{r.status}</span> },
    { id: 'version', header: 'Version', cell: (r) => r.version },
    { id: 'tools', header: 'Tools', cell: (r) => r.tools },
    { id: 'projects', header: 'Projects', cell: (r) => r.projects },
    { id: 'features', header: 'Features', cell: (r) => r.features },
  ]
}

/** /recipes: recipe records on the primitive (not the docstore), per served project. */
export function RecipesRoute() {
  useDocumentTitle('Recipes')
  const { project } = parseRecipesSearch(useSearch({ strict: false }) as Record<string, unknown>)
  const client = createRecipeClient(project)
  const list = useQuery({ queryKey: ['recipes', 'list', project], queryFn: () => client.recipes.list({ limit: 50 }) })
  const items = list.data?.items ?? []
  // The list projection carries no tools/features, so each row resolves its head + latest published version.
  const details = useQueries({
    queries: items.map((it) => ({ queryKey: ['recipes', 'get', project, it.recipe_id], queryFn: () => client.recipes.get({ recipeId: it.recipe_id }) })),
  })
  const rows: RecipeRow[] = items.map((it, i) => {
    const d = details[i]?.data
    const def = versionOf(d)?.definition
    const features = ((d?.head as { related_feature_ids?: string[] } | undefined)?.related_feature_ids ?? []).join(', ')
    return {
      recipe_id: it.recipe_id,
      name: it.name,
      status: it.status,
      version: `${it.latest_published ?? '-'} (${it.version_count})`,
      tools: def ? String(def.tools.length) : details[i]?.isPending ? '...' : '-',
      projects: it.project_ids.join(', ') || '-',
      features: features || (details[i]?.isPending ? '...' : '-'),
      project,
    }
  })
  return (
    <div className="ev2-recipes">
      <PageHeader
        title="Recipes"
        count={list.data ? list.data.count : undefined}
        description="Governed recipes on the recipe primitive: lifecycle, tools, the projects and features they serve."
      />
      <nav className="ev2-recipes__projects" aria-label="Recipe project">
        {RECIPE_PROJECTS.map((p) => (
          <Link key={p} to="/recipes" search={{ project: p }} className="ev2-recipes__chip" aria-current={p === project ? 'page' : undefined}>
            {p}
          </Link>
        ))}
      </nav>
      {list.isError ? (
        <div className="ev2-recipes__error" role="alert">
          <p>Failed to load recipes: {errMsg(list.error)}</p>
          <button type="button" onClick={() => void list.refetch()}>Retry</button>
        </div>
      ) : (
        <Table<RecipeRow> columnDefinitions={columns()} items={rows} trackBy="recipe_id" empty={list.isPending ? 'Loading recipes...' : 'No recipes found.'} />
      )}
    </div>
  )
}
