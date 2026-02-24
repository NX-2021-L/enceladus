/**
 * projects.ts — API client for devops-project-service Lambda
 *
 * Handles project creation via POST /api/v1/projects with Cognito JWT auth.
 * The enceladus_id_token cookie is automatically sent via credentials:'include'.
 */

export type CreateProjectRequest = {
  name: string;
  prefix: string;
  summary: string;
  status: string;
  parent?: string;
  repo?: string;
};

export type CreateProjectResponse = {
  success: boolean;
  project: {
    project_id: string;
    prefix: string;
    path: string;
    repo?: string;
    summary: string;
    status: string;
    parent?: string;
    created_at: string;
    updated_at: string;
    created_by: string;
  };
  initialization: Record<string, string>;
};

export class ProjectServiceError extends Error {
  public status: number;
  public details?: Record<string, unknown>;

  constructor(
    status: number,
    message: string,
    details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ProjectServiceError';
    this.status = status;
    this.details = details;
  }
}

const CANONICAL_PROJECTS_URL = '/api/v1/projects';

function normalizeApiBaseUrl(value: string | undefined): string {
  const raw = (value ?? '/api/v1').trim();
  if (!raw) return '/api/v1';
  const withLeadingSlash = raw.startsWith('/') ? raw : `/${raw}`;
  return withLeadingSlash.replace(/\/+$/, '');
}

const BASE_URL = normalizeApiBaseUrl(import.meta.env.VITE_API_BASE_URL);

async function postCreateProject(
  url: string,
  data: CreateProjectRequest
): Promise<{ response: Response; body: Record<string, unknown> }> {
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
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  return { response, body };
}

/**
 * Create a new project via devops-project-service Lambda
 * Cognito JWT is automatically sent via enceladus_id_token cookie
 */
export async function createProject(
  data: CreateProjectRequest
): Promise<CreateProjectResponse> {
  const primaryUrl = `${BASE_URL}/projects`;

  try {
    let { response, body } = await postCreateProject(primaryUrl, data);
    if (response.status === 404 && primaryUrl !== CANONICAL_PROJECTS_URL) {
      ({ response, body } = await postCreateProject(CANONICAL_PROJECTS_URL, data));
    }

    if (!response.ok) {
      const errorMessage =
        body.error ||
        body.message ||
        `HTTP ${response.status}: ${response.statusText}`;

      throw new ProjectServiceError(
        response.status,
        String(errorMessage),
        body
      );
    }

    return body as unknown as CreateProjectResponse;
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
  const value = projectId.trim();
  if (!value) {
    return { valid: false, error: 'Project ID is required' };
  }
  if (value.length < 1) {
    return { valid: false, error: 'Project ID must be at least 1 character' };
  }
  if (value.length > 50) {
    return { valid: false, error: 'Project ID must be at most 50 characters' };
  }
  if (!/^[a-z][a-z0-9_-]{0,49}$/.test(value)) {
    return {
      valid: false,
      error: 'Project ID must start with a letter and only include lowercase letters, numbers, underscores, and hyphens',
    };
  }
  return { valid: true };
}

/**
 * Validate prefix format (uppercase letters only, exactly 3 chars)
 */
export function validatePrefix(prefix: string): { valid: boolean; error?: string } {
  const value = prefix.trim();
  if (!value) {
    return { valid: false, error: 'Prefix is required' };
  }
  if (!/^[A-Z]{3}$/.test(value)) {
    return {
      valid: false,
      error: 'Prefix must be exactly 3 uppercase letters (e.g., DVP)',
    };
  }
  return { valid: true };
}

/**
 * Validate summary text
 */
export function validateSummary(summary: string): { valid: boolean; error?: string } {
  const value = summary.trim();
  if (!value) {
    return { valid: false, error: 'Summary is required' };
  }
  if (value.length > 500) {
    return { valid: false, error: 'Summary must be at most 500 characters' };
  }
  return { valid: true };
}

/**
 * Validate status against backend-accepted values
 */
export function validateProjectStatus(status: string): { valid: boolean; error?: string } {
  if (!status.trim()) {
    return { valid: false, error: 'Status is required' };
  }
  const allowed = new Set(['planning', 'development', 'active_production']);
  if (!allowed.has(status)) {
    return {
      valid: false,
      error: 'Status must be planning, development, or active_production',
    };
  }
  return { valid: true };
}

/**
 * Validate optional parent project ID
 */
export function validateParent(parent: string): { valid: boolean; error?: string } {
  const value = parent.trim();
  if (!value) return { valid: true };
  if (!/^[a-z][a-z0-9_-]{0,49}$/.test(value)) {
    return {
      valid: false,
      error: 'Parent must match project ID format (lowercase, numbers, _ or -)',
    };
  }
  return { valid: true };
}

/**
 * Validate optional repository URL
 */
export function validateRepo(repo: string): { valid: boolean; error?: string } {
  const value = repo.trim();
  if (!value) return { valid: true }; // Optional field

  // Basic URL validation - check if it's a valid URL format
  try {
    new URL(value);
    return { valid: true };
  } catch {
    return {
      valid: false,
      error: 'Repository URL must be a valid URL (e.g., https://github.com/user/repo)',
    };
  }
}
