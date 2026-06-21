// Mirrors the backend Pydantic schemas (app/schemas, app/models/enums).

export type Role = 'admin' | 'analyst' | 'viewer'
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus = 'open' | 'acknowledged' | 'resolved' | 'false_positive'

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
export const ALERT_STATUSES: AlertStatus[] = ['open', 'acknowledged', 'resolved', 'false_positive']

export interface User {
  id: number
  username: string
  email: string
  role: Role
  is_active: boolean
  created_at: string
  last_login: string | null
}

export interface Token {
  access_token: string
  token_type: string
  expires_in: number
}

export interface Alert {
  id: number
  event_id: number | null
  rule_id: number | null
  source_ip: string | null
  title: string
  description: string | null
  severity: Severity
  mitre_technique: string | null
  score: number
  status: AlertStatus
  created_at: string
  updated_at: string
}

export interface AlertFilters {
  status?: AlertStatus
  severity?: Severity
  source_ip?: string
  limit?: number
  offset?: number
}
