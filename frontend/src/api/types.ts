// Mirrors the backend Pydantic schemas (app/schemas, app/models/enums).

export type Role = 'admin' | 'analyst' | 'viewer'
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus = 'open' | 'acknowledged' | 'resolved' | 'false_positive'
export type SourceType = 'auth_log' | 'nginx' | 'apache' | 'suricata' | 'custom'

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

export interface Enrichment {
  country: string | null
  city: string | null
  latitude: number | null
  longitude: number | null
  abuse_score: number | null
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
  technique_name?: string | null
  tactic?: string | null
  score: number
  status: AlertStatus
  created_at: string
  updated_at: string
  enrichment?: Enrichment | null
}

export interface MitreCoverage {
  technique: string
  name: string | null
  tactic: string | null
  rule_count: number
  alert_count: number
}

export interface AlertFilters {
  status?: AlertStatus
  severity?: Severity
  source_ip?: string
  limit?: number
  offset?: number
}

export interface AnalyzeRequest {
  text: string
  // Omit / null to let the backend auto-detect the format.
  source_type?: SourceType | null
  source_name?: string
}

export interface AnalyzeResult {
  detected_source_type: SourceType
  auto_detected: boolean
  received: number
  parsed: number
  skipped: number
  alerts: Alert[]
}

export interface ClearResult {
  deleted: Record<string, number>
}
