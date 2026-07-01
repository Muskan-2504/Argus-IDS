// Thin typed wrapper over fetch. The bearer token is persisted in
// localStorage and attached automatically to every request.

import type {
  Alert,
  AlertFilters,
  AlertStatus,
  AnalyzeRequest,
  AnalyzeResult,
  ClearResult,
  MitreCoverage,
  Token,
  User,
} from './types'

const BASE = import.meta.env.VITE_API_URL ?? ''
const TOKEN_KEY = 'argus_token'

export const tokenStore = {
  get: (): string | null => localStorage.getItem(TOKEN_KEY),
  set: (token: string): void => localStorage.setItem(TOKEN_KEY, token),
  clear: (): void => localStorage.removeItem(TOKEN_KEY),
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  const token = tokenStore.get()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')

  const response = await fetch(`${BASE}${path}`, { ...options, headers })
  if (!response.ok) {
    throw new ApiError(response.status, await errorDetail(response))
  }
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

async function errorDetail(response: Response): Promise<string> {
  try {
    const data = await response.json()
    if (typeof data?.detail === 'string') return data.detail
  } catch {
    // fall through to status text
  }
  return response.statusText || 'Request failed'
}

function toQuery(filters: AlertFilters): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== '') params.set(key, String(value))
  }
  const query = params.toString()
  return query ? `?${query}` : ''
}

export const api = {
  async login(username: string, password: string): Promise<Token> {
    const body = new URLSearchParams({ username, password })
    const response = await fetch(`${BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    if (!response.ok) throw new ApiError(response.status, await errorDetail(response))
    return (await response.json()) as Token
  },

  me: (): Promise<User> => request<User>('/api/auth/me'),

  listAlerts: (filters: AlertFilters = {}): Promise<Alert[]> =>
    request<Alert[]>(`/api/alerts${toQuery(filters)}`),

  getAlert: (id: number): Promise<Alert> => request<Alert>(`/api/alerts/${id}`),

  updateAlertStatus: (id: number, status: AlertStatus): Promise<Alert> =>
    request<Alert>(`/api/alerts/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),

  analyzeLogs: (payload: AnalyzeRequest): Promise<AnalyzeResult> =>
    request<AnalyzeResult>('/api/ingest/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  clearData: (): Promise<ClearResult> =>
    request<ClearResult>('/api/maintenance/clear', { method: 'POST' }),

  mitreCoverage: (): Promise<MitreCoverage[]> =>
    request<MitreCoverage[]>('/api/detection/mitre-coverage'),
}
