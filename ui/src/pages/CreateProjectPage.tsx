/**
 * CreateProjectPage.tsx — Project creation form
 *
 * Renders a form that allows authenticated users to create new projects
 * via the devops-project-service Lambda endpoint.
 */

import { useState } from 'react';
import {
  createProject,
  validateProjectId,
  validatePrefix,
  validateProjectStatus,
  validateParent,
  validateSummary,
  validateRepo,
  ProjectServiceError,
} from '../api/projects';

interface FormData {
  project_id: string;
  prefix: string;
  summary: string;
  status: string;
  parent: string;
  repo: string;
}

interface FormErrors {
  project_id?: string;
  prefix?: string;
  summary?: string;
  status?: string;
  parent?: string;
  repo?: string;
  submit?: string;
}

interface SubmissionState {
  isLoading: boolean;
  success: boolean;
  successMessage?: string;
  error?: string;
}

const STATUS_OPTIONS = [
  { value: 'planning', label: 'Planning' },
  { value: 'development', label: 'Development' },
  { value: 'active_production', label: 'Active Production' },
];

export function CreateProjectPage() {
  const [formData, setFormData] = useState<FormData>({
    project_id: '',
    prefix: '',
    summary: '',
    status: 'development',
    parent: 'devops',
    repo: '',
  });

  const [errors, setErrors] = useState<FormErrors>({});
  const [submission, setSubmission] = useState<SubmissionState>({
    isLoading: false,
    success: false,
  });

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
    // Clear error for this field when user starts typing
    if (errors[name as keyof FormErrors]) {
      setErrors((prev) => ({
        ...prev,
        [name]: undefined,
      }));
    }
  };

  const validateForm = (): boolean => {
    const newErrors: FormErrors = {};

    const projectIdValidation = validateProjectId(formData.project_id);
    if (!projectIdValidation.valid) {
      newErrors.project_id = projectIdValidation.error;
    }

    const prefixValidation = validatePrefix(formData.prefix);
    if (!prefixValidation.valid) {
      newErrors.prefix = prefixValidation.error;
    }

    const summaryValidation = validateSummary(formData.summary);
    if (!summaryValidation.valid) {
      newErrors.summary = summaryValidation.error;
    }

    const statusValidation = validateProjectStatus(formData.status);
    if (!statusValidation.valid) {
      newErrors.status = statusValidation.error;
    }

    const parentValidation = validateParent(formData.parent);
    if (!parentValidation.valid) {
      newErrors.parent = parentValidation.error;
    }

    const repoValidation = validateRepo(formData.repo);
    if (!repoValidation.valid) {
      newErrors.repo = repoValidation.error;
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setSubmission({ isLoading: true, success: false });

    try {
      const payload = {
        name: formData.project_id.trim(),
        prefix: formData.prefix.trim().toUpperCase(),
        summary: formData.summary.trim(),
        status: formData.status,
        ...(formData.parent.trim() ? { parent: formData.parent.trim() } : {}),
        ...(formData.repo.trim() ? { repo: formData.repo.trim() } : {}),
      };

      const response = await createProject(payload);
      const createdProjectId = response.project.project_id;

      setSubmission({
        isLoading: false,
        success: true,
        successMessage: `Project "${createdProjectId}" created successfully.`,
      });

      // Reset form after successful submission
      setTimeout(() => {
        setFormData({
          project_id: '',
          prefix: '',
          summary: '',
          status: 'development',
          parent: 'devops',
          repo: '',
        });
        setSubmission({ isLoading: false, success: false });
        // Optionally redirect to projects list or new project
        window.location.href = `/enceladus/projects/${createdProjectId}`;
      }, 2000);
    } catch (error) {
      let errorMessage = 'Failed to create project';

      if (error instanceof ProjectServiceError) {
        if (error.status === 401) {
          errorMessage = 'Your session has expired. Please log in again.';
        } else if (error.status === 409) {
          errorMessage = `Project "${formData.project_id}" already exists.`;
        } else if (error.status === 400) {
          errorMessage = `Validation error: ${error.message}`;
        } else if (error.status === 404) {
          errorMessage = 'Create Project API route not found. Please contact support.';
        } else {
          errorMessage = error.message;
        }
      } else if (error instanceof Error) {
        errorMessage = error.message;
      }

      setSubmission({
        isLoading: false,
        success: false,
        error: errorMessage,
      });
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-4">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-100 mb-2">Create New Project</h1>
        <p className="text-sm text-slate-400">
          Create a new project in the Enceladus platform. The project will be registered with
          all necessary infrastructure components.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6 bg-slate-800 p-6 rounded-lg shadow-sm border border-slate-700">
        {/* Success Message */}
        {submission.success && submission.successMessage && (
          <div className="p-4 bg-green-900/20 border border-green-700 rounded-lg">
            <p className="text-sm font-medium text-green-300">{submission.successMessage}</p>
            <p className="text-xs text-green-400 mt-1">Redirecting to project...</p>
          </div>
        )}

        {/* Error Message */}
        {submission.error && (
          <div className="p-4 bg-red-900/20 border border-red-700 rounded-lg">
            <p className="text-sm font-medium text-red-300">{submission.error}</p>
          </div>
        )}

        {/* Project ID */}
        <div>
          <label htmlFor="project_id" className="block text-sm font-medium text-slate-200 mb-1">
            Project ID <span className="text-red-400">*</span>
          </label>
          <input
            type="text"
            id="project_id"
            name="project_id"
            value={formData.project_id}
            onChange={handleChange}
            placeholder="e.g., my-project"
            disabled={submission.isLoading}
            className={`w-full px-3 py-2 border rounded-lg text-sm font-mono bg-slate-700 text-slate-100 placeholder-slate-500 ${
              errors.project_id ? 'border-red-500' : 'border-slate-600'
            } disabled:bg-slate-600 disabled:text-slate-400`}
          />
          {errors.project_id && (
            <p className="text-xs text-red-400 mt-1">{errors.project_id}</p>
          )}
          <p className="text-xs text-slate-400 mt-1">
            Must start with a letter; lowercase letters, numbers, underscores, and hyphens are allowed.
          </p>
        </div>

        {/* Prefix */}
        <div>
          <label htmlFor="prefix" className="block text-sm font-medium text-slate-200 mb-1">
            Prefix <span className="text-red-400">*</span>
          </label>
          <input
            type="text"
            id="prefix"
            name="prefix"
            value={formData.prefix}
            onChange={handleChange}
            placeholder="e.g., MP"
            maxLength={3}
            disabled={submission.isLoading}
            className={`w-full px-3 py-2 border rounded-lg text-sm font-mono uppercase bg-slate-700 text-slate-100 placeholder-slate-500 ${
              errors.prefix ? 'border-red-500' : 'border-slate-600'
            } disabled:bg-slate-600 disabled:text-slate-400`}
          />
          {errors.prefix && <p className="text-xs text-red-400 mt-1">{errors.prefix}</p>}
          <p className="text-xs text-slate-400 mt-1">
            Exactly 3 uppercase letters. Used for record IDs (e.g., DVP-TSK-001).
          </p>
        </div>

        {/* Summary */}
        <div>
          <label htmlFor="summary" className="block text-sm font-medium text-slate-200 mb-1">
            Summary <span className="text-red-400">*</span>
          </label>
          <textarea
            id="summary"
            name="summary"
            value={formData.summary}
            onChange={handleChange}
            placeholder="Brief description of the project..."
            rows={3}
            disabled={submission.isLoading}
            className={`w-full px-3 py-2 border rounded-lg text-sm bg-slate-700 text-slate-100 placeholder-slate-500 ${
              errors.summary ? 'border-red-500' : 'border-slate-600'
            } disabled:bg-slate-600 disabled:text-slate-400`}
          />
          {errors.summary && (
            <p className="text-xs text-red-400 mt-1">{errors.summary}</p>
          )}
          <p className="text-xs text-slate-400 mt-1">
            1-500 characters. Describe the project's purpose and scope.
          </p>
        </div>

        {/* Status */}
        <div>
          <label htmlFor="status" className="block text-sm font-medium text-slate-200 mb-1">
            Status <span className="text-red-400">*</span>
          </label>
          <select
            id="status"
            name="status"
            value={formData.status}
            onChange={handleChange}
            disabled={submission.isLoading}
            className={`w-full px-3 py-2 border rounded-lg text-sm bg-slate-700 text-slate-100 ${
              errors.status ? 'border-red-500' : 'border-slate-600'
            } disabled:bg-slate-600 disabled:text-slate-400`}
          >
            {STATUS_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          {errors.status && <p className="text-xs text-red-400 mt-1">{errors.status}</p>}
        </div>

        {/* Parent Project */}
        <div>
          <label htmlFor="parent" className="block text-sm font-medium text-slate-200 mb-1">
            Parent Project
          </label>
          <input
            type="text"
            id="parent"
            name="parent"
            value={formData.parent}
            onChange={handleChange}
            placeholder="e.g., devops"
            disabled={submission.isLoading}
            className={`w-full px-3 py-2 border rounded-lg text-sm font-mono bg-slate-700 text-slate-100 placeholder-slate-500 ${
              errors.parent ? 'border-red-500' : 'border-slate-600'
            } disabled:bg-slate-600 disabled:text-slate-400`}
          />
          {errors.parent && (
            <p className="text-xs text-red-400 mt-1">{errors.parent}</p>
          )}
          <p className="text-xs text-slate-400 mt-1">
            Optional project ID for hierarchy (for top-level projects leave blank).
          </p>
        </div>

        {/* Repository URL */}
        <div>
          <label htmlFor="repo" className="block text-sm font-medium text-slate-200 mb-1">
            Repository URL
          </label>
          <input
            type="text"
            id="repo"
            name="repo"
            value={formData.repo}
            onChange={handleChange}
            placeholder="e.g., https://github.com/user/repo"
            disabled={submission.isLoading}
            className={`w-full px-3 py-2 border rounded-lg text-sm bg-slate-700 text-slate-100 placeholder-slate-500 ${
              errors.repo ? 'border-red-500' : 'border-slate-600'
            } disabled:bg-slate-600 disabled:text-slate-400`}
          />
          {errors.repo && (
            <p className="text-xs text-red-400 mt-1">{errors.repo}</p>
          )}
          <p className="text-xs text-slate-400 mt-1">
            Optional link to the project's repository (e.g., GitHub URL).
          </p>
        </div>

        {/* Submit Button */}
        <div className="flex gap-3 pt-4">
          <button
            type="submit"
            disabled={submission.isLoading || submission.success}
            className="flex-1 px-4 py-2 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 disabled:bg-slate-600 disabled:cursor-not-allowed transition-colors"
          >
            {submission.isLoading ? 'Creating Project...' : 'Create Project'}
          </button>
          <button
            type="button"
            disabled={submission.isLoading}
            onClick={() => window.history.back()}
            className="px-4 py-2 border border-slate-600 text-slate-300 font-medium rounded-lg hover:bg-slate-700 disabled:bg-slate-700 disabled:text-slate-500 transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
