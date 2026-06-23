import type { ReactNode } from 'react'

import {
  ALERT_STATUSES,
  SEVERITY_ORDER,
  type AlertFilters as Filters,
  type AlertStatus,
  type Severity,
} from '../api/types'
import { STATUS_LABELS } from '../lib/labels'

interface Props {
  filters: Filters
  onChange: (filters: Filters) => void
}

const SELECT = 'rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm outline-none focus:border-sky-500'

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-xs text-slate-400">
      {label}
      {children}
    </label>
  )
}

export function AlertFilters({ filters, onChange }: Props) {
  return (
    <div className="flex flex-wrap items-end gap-3">
      <Field label="Severity">
        <select
          className={SELECT}
          value={filters.severity ?? ''}
          onChange={(e) =>
            onChange({ ...filters, severity: (e.target.value || undefined) as Severity | undefined })
          }
        >
          <option value="">All</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </Field>

      <Field label="Status">
        <select
          className={SELECT}
          value={filters.status ?? ''}
          onChange={(e) =>
            onChange({ ...filters, status: (e.target.value || undefined) as AlertStatus | undefined })
          }
        >
          <option value="">All</option>
          {ALERT_STATUSES.map((s) => (
            <option key={s} value={s}>
              {STATUS_LABELS[s]}
            </option>
          ))}
        </select>
      </Field>

      <Field label="Source IP">
        <input
          className={SELECT}
          placeholder="e.g. 203.0.113.5"
          value={filters.source_ip ?? ''}
          onChange={(e) => onChange({ ...filters, source_ip: e.target.value || undefined })}
        />
      </Field>
    </div>
  )
}
