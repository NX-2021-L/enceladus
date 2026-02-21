/**
 * projects.ts — API client for devops-project-service Lambda
 *
 * Handles project creation via POST /api/v1/projects with Cognito JWT auth.
 * The enceladus_id_token cookie is automatically sent via credentials:'include'.
 */

export interface CreateProjectRequest {
  project_id: string;
  prefix: string;
  path: string;
  summary: string;
  status: string;
  parent: string;
}

export interface CreateProjectResponse {
  project_id: string;
  created_at: string;
  reference_doc_id: string;
}

export class ProjectServiceError extends Error {
  constructor(
    public status: number,
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ProjectServiceError';
  }
}

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

/**
 * Create a new project via devops-project-service Lambda
 * Cognito JWT is automatically sent via enceladus_id_token cookie
 */
export async function createProject(
  data: CreateProjectRequest
): Promise<CreateProjectResponse> {
  const url = `${BASE_URL}/projects`;

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      // Credentials: include ensures enceladus_id_token cookie is sent
      credentials: 'include',
      body: JSON.stringify(data),
    });

    const responseData = await response.json().catch(() => ({}));

    if (!response.ok) {
      const errorMessage =
        (responseData as Record<string, unknown>)?.error ||
        (responseData as Record<string, unknown>)?.message ||
        `HTTP ${response.status}: ${response.statusText}`;

      throw new ProjectServiceError(
        response.status,
        String(errorMessage),
        responseData as Record<string, unknown>
      );
    }

    return responseData as CreateProjectResponse;
  } catch (error) {
    if (error instanceof ProjectServiceError) {
      throw error;
    }

    if (error instanceof Error) {
      throw new ProjectServiceError(0, `Network error: ${error.message}`);
    }

    throw new ProjectServiceError(0, 'Unknown error occurred');
  }
}

/**
 * Validate project_id format (lowercase, hyphens, alphanumeric)
 */
export function validateProjectId(projectId: string): {
  valid: boolean;
  error?: string;
} {
  if (!projectId.trim()) {
    return { valid: false, error: 'Project ID is required' };
  }
  if (projectId.length < 3) {
    return { valid: false, error: 'Project ID must be at least 3 characters' };
  }
  if (projectId.length > 50) {
    return { valid: false, error: 'Project ID must be at most 50 characters' };
  }
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(projectId)) {
    return {
      valid: false,
      error: 'Project ID must be lowercase letters, numbers, and hyphens (no leading/trailing hyphens)',
    };
  }
  return { valid: true };
}

/**
 * Validate prefix format (uppercase letters only, 2-3 chars)
 */
export function validatePrefix(prefix: string): { valid: boolean; error?: string } {
  if (!prefix.trim()) {
    return { valid: false, error: 'Prefix is required' };
  }
  if (!/^[A-Z]{2,3}$/.test(prefix)) {
    return {
      valid: false,
      error: 'Prefix must be 2-3 uppercase letters only (e.g., ENC, DVP)',
    };
  }
  return { valid: true };
}

/**
 * Validate path format
 */
export function validatePath(path: string): { valid: boolean; error?: string } {
  if (!path.trim()) {
    return { valid: false, error: 'Path is required' };
  }
  if (!/^[a-z0-9][a-z0-9\-/]*[a-z0-9]$/.test(path) && path.length > 2) {
    return {
      valid: false,
      error: 'Path must be lowercase letters, numbers, hyphens, and forward slashes',
    };
  }
  return { valid: true };
}

/**
 * Validate summary text
 */
export function validateSummary(summary: string): { valid: boolean; error?: string } {
  if (!summary.trim()) {
    return { valid: false, error: 'Summary is required' };
  }
  if (summary.length < 10) {
    return { valid: false, error: 'Summary must be at least 10 characters' };
  }
  if (summary.length > 500) {
    return { valid: false, error: 'Summary must be at most 500 characters' };
  }
  return { valid: true };
}
