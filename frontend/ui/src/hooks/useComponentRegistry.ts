/**
 * useComponentRegistry.ts — React Query hooks for component registry (ENC-FTR-041)
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  fetchComponents,
  createComponent,
  updateComponent,
  deleteComponent,
  componentKeys,
  type ComponentFilters,
  type CreateComponentInput,
  type UpdateComponentInput,
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
