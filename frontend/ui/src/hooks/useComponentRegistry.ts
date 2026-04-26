/**
 * useComponentRegistry.ts — React Query hooks for component registry (ENC-FTR-041)
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  fetchComponents,
  createComponent,
  updateComponent,
  deleteComponent,
  approveComponent,
  rejectComponent,
  revertComponent,
  deprecateComponent,
  restoreComponent,
  advanceComponent,
  componentKeys,
  type ComponentFilters,
  type CreateComponentInput,
  type UpdateComponentInput,
  type ApproveComponentInput,
  type RejectComponentInput,
  type RevertComponentInput,
  type DeprecateComponentInput,
  type RestoreComponentInput,
  type AdvanceComponentInput,
} from '../api/components'

export function useComponentRegistry(filters: ComponentFilters = {}) {
  const query = useQuery({
    queryKey: componentKeys.list(filters),
    queryFn: () => fetchComponents(filters),
    staleTime: 30_000,
  })
  return {
    components: query.data?.components ?? [],
    count: query.data?.count ?? 0,
    ...query,
  }
}

export function useCreateComponent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateComponentInput) => createComponent(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: componentKeys.all }),
  })
}

export function useUpdateComponent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateComponentInput }) =>
      updateComponent(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: componentKeys.all }),
  })
}

export function useDeleteComponent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (componentId: string) => deleteComponent(componentId),
    onSuccess: () => qc.invalidateQueries({ queryKey: componentKeys.all }),
  })
}

// ENC-FTR-076 Phase 6: Approve/reject mutations

export function useApproveComponent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: ApproveComponentInput) => approveComponent(input),
    onSuccess: () => qc.invalidateQueries({ queryKey: componentKeys.all }),
  })
}

export function useRejectComponent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: RejectComponentInput) => rejectComponent(input),
    onSuccess: () => qc.invalidateQueries({ queryKey: componentKeys.all }),
  })
}

// ENC-FTR-076 v2 / ENC-TSK-F44 — lifecycle action hooks
// These POST to endpoints that F40 delivers. Pre-F40-deploy they 404 (UI only).

export function useRevertComponent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: RevertComponentInput) => revertComponent(input),
    onSuccess: () => qc.invalidateQueries({ queryKey: componentKeys.all }),
  })
}

export function useDeprecateComponent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: DeprecateComponentInput) => deprecateComponent(input),
    onSuccess: () => qc.invalidateQueries({ queryKey: componentKeys.all }),
  })
}

export function useRestoreComponent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: RestoreComponentInput) => restoreComponent(input),
    onSuccess: () => qc.invalidateQueries({ queryKey: componentKeys.all }),
  })
}

export function useAdvanceComponent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: AdvanceComponentInput) => advanceComponent(input),
    onSuccess: () => qc.invalidateQueries({ queryKey: componentKeys.all }),
  })
}
