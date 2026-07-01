import type { AlertStatus, SourceType } from '../api/types'

export const STATUS_LABELS: Record<AlertStatus, string> = {
  open: 'Open',
  acknowledged: 'Acknowledged',
  resolved: 'Resolved',
  false_positive: 'False positive',
}

export const SOURCE_TYPE_LABELS: Record<SourceType, string> = {
  auth_log: 'SSH auth log',
  nginx: 'Web access log (nginx)',
  apache: 'Web access log (apache)',
  suricata: 'Suricata EVE JSON',
  custom: 'Generic (auto-extracted)',
}

// The formats a user can pick on the Analyze page. 'custom' is the generic
// extractor that handles arbitrary formats (JSON, key=value, or free text).
export const ANALYZABLE_FORMATS: { value: SourceType; label: string; hint: string }[] = [
  { value: 'auth_log', label: 'SSH auth log', hint: 'Linux /var/log/auth.log' },
  { value: 'nginx', label: 'Web access log', hint: 'nginx or apache access.log' },
  { value: 'suricata', label: 'Suricata EVE JSON', hint: 'eve.json alerts' },
  { value: 'custom', label: 'Any / other format', hint: 'JSON, key=value, or free text' },
]
