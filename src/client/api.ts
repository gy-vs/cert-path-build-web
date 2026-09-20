import type {FixturesResponse, ValidationReport} from './types';

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data?.message ?? data?.error ?? `request failed: ${response.status}`);
  return data as T;
}

export type ValidateParams = {
  certPems: string[];
  anchorPems: string[];
  verificationTime: string;
  policy: {minRsaBits: number; allowSha1: boolean};
  policyRevision: number;
  target?: string;
};

export const api = {
  fixtures: () => fetch('/api/fixtures').then(r => r.json() as Promise<FixturesResponse>),
  validate: (params: ValidateParams) => postJson<ValidationReport>('/api/validate', params),
};
