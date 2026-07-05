/**
 * Projects page (ENC-TSK-L31 / B67 PWA 2.0) — PWA 1.0 parity
 * (frontend/ui/src/pages/ProjectsListPage.tsx + CreateProjectPage.tsx) rebuilt
 * in design-system-2: Cards for the 25+ project registry, Modal + Form for
 * the create-project flow. Reads through projectRegistryQueryOptions (the
 * same GET /api/v1/projects the app already uses for AuthGate / record-id
 * resolution); creates through api/projects.ts createProject(), which hits
 * the existing project_service POST /api/v1/projects handler — no backend
 * changes were needed for this page.
 */
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Box,
  Button,
  Cards,
  Form,
  FormField,
  Header,
  Input,
  Modal,
  Select,
} from '../design-system'
import { projectRegistryKeys, projectRegistryQueryOptions } from '../api/projectRegistry'
import {
  createProject,
  validatePrefix,
  validateProjectId,
  validateRepo,
  validateSummary,
  PROJECT_STATUS_OPTIONS,
  ProjectCreateError,
  type ProjectSummary,
} from '../api/projects'
import { SessionExpiredError } from '../api/client'
import { StatusChip } from '../components/StatusChip'

function formatUpdatedAt(value?: string): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

interface CreateProjectFormState {
  name: string
  prefix: string
  summary: string
  status: string
  parent: string
  repo: string
}

const EMPTY_FORM: CreateProjectFormState = {
  name: '',
  prefix: '',
  summary: '',
  status: 'planning',
  parent: '',
  repo: '',
}

interface SelectOption {
  value: string
  label: string
}

const STATUS_SELECT_OPTIONS: SelectOption[] = PROJECT_STATUS_OPTIONS.map((option) => ({
  value: option.value,
  label: option.label,
}))

type FormErrors = Partial<Record<keyof CreateProjectFormState, string>> & { submit?: string }

function validateAll(form: CreateProjectFormState): FormErrors {
  const errors: FormErrors = {}
  const name = validateProjectId(form.name)
  if (!name.valid) errors.name = name.error
  const prefix = validatePrefix(form.prefix)
  if (!prefix.valid) errors.prefix = prefix.error
  const summary = validateSummary(form.summary)
  if (!summary.valid) errors.summary = summary.error
  const repo = validateRepo(form.repo)
  if (!repo.valid) errors.repo = repo.error
  return errors
}

export function ProjectsRoute() {
  const { data: projects = [], isPending, isError } = useQuery(projectRegistryQueryOptions)
  const queryClient = useQueryClient()

  const [modalVisible, setModalVisible] = useState(false)
  const [form, setForm] = useState<CreateProjectFormState>(EMPTY_FORM)
  const [errors, setErrors] = useState<FormErrors>({})

  const createMutation = useMutation({
    mutationFn: () =>
      createProject({
        name: form.name.trim(),
        prefix: form.prefix.trim().toUpperCase(),
        summary: form.summary.trim(),
        status: form.status,
        ...(form.parent.trim() ? { parent: form.parent.trim() } : {}),
        ...(form.repo.trim() ? { repo: form.repo.trim() } : {}),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: projectRegistryKeys.all })
      setModalVisible(false)
      setForm(EMPTY_FORM)
      setErrors({})
    },
  })

  const openModal = () => {
    setForm(EMPTY_FORM)
    setErrors({})
    createMutation.reset()
    setModalVisible(true)
  }

  const closeModal = () => {
    if (createMutation.isPending) return
    setModalVisible(false)
  }

  const handleSubmit = () => {
    const nextErrors = validateAll(form)
    setErrors(nextErrors)
    if (Object.keys(nextErrors).length > 0) return
    createMutation.mutate()
  }

  const submitErrorText = (() => {
    const error = createMutation.error
    if (!error) return undefined
    if (error instanceof SessionExpiredError) return 'Your session has expired. Please log in again.'
    if (error instanceof ProjectCreateError) {
      if (error.status === 409) return `Project "${form.name.trim()}" or prefix "${form.prefix.trim().toUpperCase()}" already exists.`
      if (error.status === 400) return `Validation error: ${error.message}`
      return error.message
    }
    return error instanceof Error ? error.message : 'Failed to create project'
  })()

  const cardDefinition = {
    header: (project: ProjectSummary) => (
      <span>
        <span style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: 11, opacity: 0.7, marginRight: 8 }}>
          {project.prefix}
        </span>
        {project.name ?? project.project_id}
      </span>
    ),
    sections: [
      {
        id: 'status',
        header: 'Status',
        content: (project: ProjectSummary) =>
          project.status ? <StatusChip status={project.status} /> : '—',
      },
      {
        id: 'summary',
        header: 'Summary',
        content: (project: ProjectSummary) => project.summary || '—',
      },
      {
        id: 'updated',
        header: 'Updated',
        content: (project: ProjectSummary) => formatUpdatedAt(project.updated_at),
      },
    ],
  }

  return (
    <div className="projects-route">
      <Header
        variant="h1"
        counter={`(${projects.length})`}
        description="All governed Enceladus projects. Create a new project to register it with the tracker, docstore, and reference-doc pipeline."
        actions={<Button variant="primary" onClick={openModal}>Create project</Button>}
      >
        Projects
      </Header>

      {isPending && <Box padding="l">Loading projects…</Box>}
      {isError && <Box padding="l">Failed to load projects.</Box>}
      {!isPending && !isError && projects.length === 0 && <Box padding="l">No projects found.</Box>}

      {!isPending && !isError && projects.length > 0 && (
        <Cards items={projects} trackBy="project_id" columns={3} cardDefinition={cardDefinition} />
      )}

      <Modal
        visible={modalVisible}
        header="Create project"
        size="medium"
        onDismiss={closeModal}
        footer={
          <>
            <Button variant="normal" onClick={closeModal} disabled={createMutation.isPending}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleSubmit} loading={createMutation.isPending}>
              Create project
            </Button>
          </>
        }
      >
        <Form errorText={submitErrorText}>
          <FormField
            label="Project ID"
            constraintText="Lowercase letters, numbers, underscores, and hyphens; must start with a letter."
            errorText={errors.name}
          >
            <Input
              value={form.name}
              placeholder="e.g. my-project"
              onChange={(event) => setForm((prev) => ({ ...prev, name: event.detail.value }))}
              ariaLabel="Project ID"
            />
          </FormField>

          <FormField
            label="Prefix"
            constraintText="Exactly 3 uppercase letters (e.g. DVP). Used for record IDs."
            errorText={errors.prefix}
          >
            <Input
              value={form.prefix}
              placeholder="e.g. DVP"
              mono
              onChange={(event) =>
                setForm((prev) => ({ ...prev, prefix: event.detail.value.toUpperCase() }))
              }
              ariaLabel="Prefix"
            />
          </FormField>

          <FormField label="Summary" errorText={errors.summary}>
            <Input
              value={form.summary}
              placeholder="Brief description of the project…"
              onChange={(event) => setForm((prev) => ({ ...prev, summary: event.detail.value }))}
              ariaLabel="Summary"
            />
          </FormField>

          <FormField label="Status">
            <Select
              selectedOption={
                STATUS_SELECT_OPTIONS.find((option) => option.value === form.status) ?? null
              }
              options={STATUS_SELECT_OPTIONS}
              onChange={(event) =>
                setForm((prev) => ({ ...prev, status: String(event.detail.selectedOption.value) }))
              }
            />
          </FormField>

          <FormField label="Parent project" description="Optional — leave blank for a top-level project.">
            <Input
              value={form.parent}
              placeholder="e.g. devops"
              onChange={(event) => setForm((prev) => ({ ...prev, parent: event.detail.value }))}
              ariaLabel="Parent project"
            />
          </FormField>

          <FormField label="Repository URL" description="Optional." errorText={errors.repo}>
            <Input
              value={form.repo}
              placeholder="e.g. https://github.com/org/repo"
              onChange={(event) => setForm((prev) => ({ ...prev, repo: event.detail.value }))}
              ariaLabel="Repository URL"
            />
          </FormField>
        </Form>
      </Modal>
    </div>
  )
}
