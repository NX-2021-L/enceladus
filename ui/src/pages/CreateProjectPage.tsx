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
  validatePath,
  validateSummary,
  ProjectServiceError,
} from '../api/projects';

interface FormData {
  project_id: string;
  prefix: string;
  path: string;
  summary: string;
  status: string;
  parent: string;
}

interface FormErrors {
  project_id?: string;
  prefix?: string;
  path?: string;
  summary?: string;
  status?: string;
  parent?: string;
  submit?: string;
}

interface SubmissionState {
  isLoading: boolean;
  success: boolean;
  successMessage?: string;
  error?: string;
}

const STATUS_OPTIONS = [
  { value: 'active_development', label: 'Active Development' },
  { value: 'active_production', label: 'Active Production' },
  { value: 'maintenance', label: 'Maintenance' },
  { value: 'archived', label: 'Archived' },
];

export function CreateProjectPage() {
  const [formData, setFormData] = useState<FormData>({
    project_id: '',
    prefix: '',
    path: '',
    summary: '',
    status: 'active_development',
    parent: 'devops',
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

    const pathValidation = validatePath(formData.path);
    if (!pathValidation.valid) {
      newErrors.path = pathValidation.error;
    }

    const summaryValidation = validateSummary(formData.summary);
    if (!summaryValidation.valid) {
      newErrors.summary = summaryValidation.error;
    }

    if (!formData.status.trim()) {
      newErrors.status = 'Status is required';
    }

    if (!formData.parent.trim()) {
      newErrors.parent = 'Parent project is required';
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
      const response = await createProject(formData);

      setSubmission({
        isLoading: false,
        success: true,
        successMessage: `Project "${formData.project_id}" created successfully! Reference document: ${response.reference_doc_id}`,
      });

      // Reset form after successful submission
      setTimeout(() => {
        setFormData({
          project_id: '',
          prefix: '',
          path: '',
          summary: '',
          status: 'active_development',
          parent: 'devops',
        });
        setSubmission({ isLoading: false, success: false });
        // Optionally redirect to projects list or new project
        window.location.href = `/enceladus/projects/${formData.project_id}`;
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
        <h1 className="text-2xl font-bold text-slate-900 mb-2">Create New Project</h1>
        <p className="text-sm text-slate-600">
          Create a new project in the Enceladus platform. The project will be registered with
          all necessary infrastructure components.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6 bg-white p-6 rounded-lg shadow-sm border border-slate-200">
        {/* Success Message */}
        {submission.success && submission.successMessage && (
          <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
            <p className="text-sm font-medium text-green-900">{submission.successMessage}</p>
            <p className="text-xs text-green-700 mt-1">Redirecting to project...</p>
          </div>
        )}

        {/* Error Message */}
        {submission.error && (
          <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
            <p className="text-sm font-medium text-red-900">{submission.error}</p>
          </div>
        )}

        {/* Project ID */}
        <div>
          <label htmlFor="project_id" className="block text-sm font-medium text-slate-900 mb-1">
            Project ID <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            id="project_id"
            name="project_id"
            value={formData.project_id}
            onChange={handleChange}
            placeholder="e.g., my-project"
            disabled={submission.isLoading}
            className={`w-full px-3 py-2 border rounded-lg text-sm font-mono ${
              errors.project_id ? 'border-red-500 bg-red-50' : 'border-slate-300'
            } disabled:bg-slate-100 disabled:text-slate-500`}
          />
          {errors.project_id && (
            <p className="text-xs text-red-600 mt-1">{errors.project_id}</p>
          )}
          <p className="text-xs text-slate-500 mt-1">
            Lowercase letters, numbers, and hyphens only. No leading/trailing hyphens.
          </p>
        </div>

        {/* Prefix */}
        <div>
          <label htmlFor="prefix" className="block text-sm font-medium text-slate-900 mb-1">
            Prefix <span className="text-red-500">*</span>
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
            className={`w-full px-3 py-2 border rounded-lg text-sm font-mono uppercase ${
              errors.prefix ? 'border-red-500 bg-red-50' : 'border-slate-300'
            } disabled:bg-slate-100 disabled:text-slate-500`}
          />
          {errors.prefix && <p className="text-xs text-red-600 mt-1">{errors.prefix}</p>}
          <p className="text-xs text-slate-500 mt-1">
            2-3 uppercase letters. Used for record IDs (e.g., MP-TSK-001).
          </p>
        </div>

        {/* Path */}
        <div>
          <label htmlFor="path" className="block text-sm font-medium text-slate-900 mb-1">
            Path <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            id="path"
            name="path"
            value={formData.path}
            onChange={handleChange}
            placeholder="e.g., projects/my-project"
            disabled={submission.isLoading}
            className={`w-full px-3 py-2 border rounded-lg text-sm font-mono ${
              errors.path ? 'border-red-500 bg-red-50' : 'border-slate-300'
            } disabled:bg-slate-100 disabled:text-slate-500`}
          />
          {errors.path && <p className="text-xs text-red-600 mt-1">{errors.path}</p>}
          <p className="text-xs text-slate-500 mt-1">
            Repository path for project documentation and assets.
          </p>
        </div>

        {/* Summary */}
        <div>
          <label htmlFor="summary" className="block text-sm font-medium text-slate-900 mb-1">
            Summary <span className="text-red-500">*</span>
          </label>
          <textarea
            id="summary"
            name="summary"
            value={formData.summary}
            onChange={handleChange}
            placeholder="Brief description of the project..."
            rows={3}
            disabled={submission.isLoading}
            className={`w-full px-3 py-2 border rounded-lg text-sm ${
              errors.summary ? 'border-red-500 bg-red-50' : 'border-slate-300'
            } disabled:bg-slate-100 disabled:text-slate-500`}
          />
          {errors.summary && (
            <p className="text-xs text-red-600 mt-1">{errors.summary}</p>
          )}
          <p className="text-xs text-slate-500 mt-1">
            10-500 characters. Describe the project's purpose and scope.
          </p>
        </div>

        {/* Status */}
        <div>
          <label htmlFor="status" className="block text-sm font-medium text-slate-900 mb-1">
            Status <span className="text-red-500">*</span>
          </label>
          <select
            id="status"
            name="status"
            value={formData.status}
            onChange={handleChange}
            disabled={submission.isLoading}
            className={`w-full px-3 py-2 border rounded-lg text-sm ${
              errors.status ? 'border-red-500 bg-red-50' : 'border-slate-300'
            } disabled:bg-slate-100 disabled:text-slate-500`}
          >
            {STATUS_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          {errors.status && <p className="text-xs text-red-600 mt-1">{errors.status}</p>}
        </div>

        {/* Parent Project */}
        <div>
          <label htmlFor="parent" className="block text-sm font-medium text-slate-900 mb-1">
            Parent Project <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            id="parent"
            name="parent"
            value={formData.parent}
            onChange={handleChange}
            placeholder="e.g., devops"
            disabled={submission.isLoading}
            className={`w-full px-3 py-2 border rounded-lg text-sm font-mono ${
              errors.parent ? 'border-red-500 bg-red-50' : 'border-slate-300'
            } disabled:bg-slate-100 disabled:text-slate-500`}
          />
          {errors.parent && (
            <p className="text-xs text-red-600 mt-1">{errors.parent}</p>
          )}
          <p className="text-xs text-slate-500 mt-1">
            Project ID of the parent project (typically "devops").
          </p>
        </div>

        {/* Submit Button */}
        <div className="flex gap-3 pt-4">
          <button
            type="submit"
            disabled={submission.isLoading || submission.success}
            className="flex-1 px-4 py-2 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 disabled:bg-slate-400 disabled:cursor-not-allowed transition-colors"
          >
            {submission.isLoading ? 'Creating Project...' : 'Create Project'}
          </button>
          <button
            type="button"
            disabled={submission.isLoading}
            onClick={() => window.history.back()}
            className="px-4 py-2 border border-slate-300 text-slate-700 font-medium rounded-lg hover:bg-slate-50 disabled:bg-slate-100 disabled:text-slate-500 transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
