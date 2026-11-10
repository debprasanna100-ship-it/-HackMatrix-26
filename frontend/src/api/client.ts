import { getAuthToken, notifyUnauthorized, setAuthToken } from './auth'
import type {
  AnalysisReport,
  ChainCommitment,
  CorrelationResult,
  ReportListResponse,
  SuppliedVerifyResult,
  VerifyResult,
} from './types'

/** Error thrown for any non-2xx backend response or a network failure. */
export class ApiError extends Error {
  code: string
  status: number

  constructor(code: string, message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.status = status
  }
}

interface ErrorBody {
  error?: { code?: string; message?: string; details?: unknown }
  detail?: unknown
}

function extractError(status: number, body: unknown): ApiError {
  // TrustLens shape: {"error": {"code", "message"}}
  if (body && typeof body === 'object' && 'error' in body) {
    const err = (body as ErrorBody).error
    if (err && typeof err === 'object') {
      return new ApiError(err.code ?? 'http_error', err.message ?? 'Request failed.', status)
    }
  }
  // FastAPI HTTPException shape: {"detail": "..." | {...}}
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail = (body as ErrorBody).detail
    if (typeof detail === 'string') {
      return new ApiError('http_error', detail, status)
    }
    if (detail && typeof detail === 'object') {
      const d = detail as { code?: string; message?: string }
      return new ApiError(d.code ?? 'http_error', d.message ?? JSON.stringify(detail), status)
    }
  }
  return new ApiError('http_error', `Request failed with status ${status}.`, status)
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  // Audit M3: attach the Bearer token when a session exists. A 401 answered
  // WHILE a token was attached means the session expired or was revoked —
  // drop the token and let the UI reset to the login state. A 401 without a
  // token (e.g. a failed login attempt) is passed through untouched.
  const token = getAuthToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }
  let resp: Response
  try {
    resp = await fetch(path, {
      ...init,
      headers: { ...headers, ...((init?.headers as Record<string, string>) ?? {}) },
    })
  } catch {
    throw new ApiError(
      'network_error',
      'Could not reach the TrustLens backend. Make sure the API is running on port 8000.',
      0,
    )
  }
  if (!resp.ok) {
    let body: unknown = null
    try {
      body = await resp.json()
    } catch {
      // non-JSON error body
    }
    if (resp.status === 401 && token) {
      notifyUnauthorized()
    }
    throw extractError(resp.status, body)
  }
  return (await resp.json()) as T
}

/** Identity payload of GET /api/v1/auth/me. */
export interface AuthMe {
  authenticated: boolean
  mode?: string
  user_id?: string
  email?: string
  role?: string
  email_verified?: boolean
}

/** Probe the caller's identity WITHOUT auth side effects: in demo mode the
 *  backend answers 200 (authenticated: false, mode "auth_disabled"); with
 *  auth required and no/invalid credentials it answers 401, which the
 *  AuthBar uses to show the login form. Unlike request(), this never clears
 *  the session token or fires the unauthorized handler. */
export async function fetchMe(): Promise<AuthMe> {
  let resp: Response
  try {
    const token = getAuthToken()
    resp = await fetch('/api/v1/auth/me', {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
  } catch {
    throw new ApiError('network_error', 'Could not reach the TrustLens backend.', 0)
  }
  if (!resp.ok) {
    throw extractError(resp.status, null)
  }
  return (await resp.json()) as AuthMe
}

/** Email + password login (POST /api/v1/auth/token). Stores the returned
 *  bearer token for all subsequent API calls and resolves to the caller's
 *  identity. Throws ApiError on wrong credentials. */
export async function login(email: string, password: string): Promise<AuthMe> {
  const result = await request<{ access_token: string; token_type: string }>(
    '/api/v1/auth/token',
    { method: 'POST', body: JSON.stringify({ email, password }) },
  )
  setAuthToken(result.access_token)
  return fetchMe()
}

/** Drop the local session. The backend JWT is stateless, so there is no
 *  server-side logout endpoint to call (audit M3). */
export function logout(): void {
  setAuthToken(null)
}

export function analyzeUrl(url: string): Promise<AnalysisReport> {
  return request<AnalysisReport>('/api/v1/analyze/url', {
    method: 'POST',
    body: JSON.stringify({ url }),
  })
}

export function analyzeMessage(message: string): Promise<AnalysisReport> {
  return request<AnalysisReport>('/api/v1/analyze/message', {
    method: 'POST',
    body: JSON.stringify({ message }),
  })
}

export function getReport(reportId: string): Promise<AnalysisReport> {
  return request<AnalysisReport>(`/api/v1/reports/${encodeURIComponent(reportId)}`)
}

export function deleteReport(reportId: string): Promise<{ deleted: boolean; report_id: string }> {
  return request<{ deleted: boolean; report_id: string }>(
    `/api/v1/reports/${encodeURIComponent(reportId)}`,
    { method: 'DELETE' },
  )
}

export function listReports(limit = 20, offset = 0): Promise<ReportListResponse> {
  return request<ReportListResponse>(`/api/v1/reports?limit=${limit}&offset=${offset}`)
}

export function commitReport(reportId: string): Promise<ChainCommitment> {
  return request<ChainCommitment>(`/api/v1/reports/${encodeURIComponent(reportId)}/commit`, {
    method: 'POST',
  })
}

export function verifyIdentifier(idOrHash: string): Promise<VerifyResult> {
  return request<VerifyResult>(`/api/v1/verify/${encodeURIComponent(idOrHash.trim())}`)
}

/** Verify a supplied (pasted/exported) report JSON against its own integrity
 *  hash, an optional expected hash, and the on-chain commitment. */
export function verifyReportJson(reportText: string, expectedHash?: string): Promise<SuppliedVerifyResult> {
  let report: unknown
  try {
    report = JSON.parse(reportText)
  } catch {
    return Promise.reject(new ApiError('invalid_json', 'The pasted report is not valid JSON.', 400))
  }
  const body: Record<string, unknown> = { report }
  if (expectedHash && expectedHash.trim()) body.expected_hash = expectedHash.trim()
  return request<SuppliedVerifyResult>('/api/v1/verify/report', {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

export function correlateReport(reportId: string): Promise<CorrelationResult> {
  return request<CorrelationResult>(`/api/v1/correlate/${encodeURIComponent(reportId)}`)
}
