import type { Alert } from '../api/types'
import { formatTimestamp } from '../lib/format'
import { SeverityBadge } from './SeverityBadge'

export function LiveFeed({ alerts }: { alerts: Alert[] }) {
  if (alerts.length === 0) {
    return <p className="py-6 text-center text-sm text-slate-500">Waiting for live alerts…</p>
  }
  return (
    <ul className="space-y-2">
      {alerts.map((alert) => (
        <li key={alert.id} className="flex items-start gap-2 text-sm">
          <SeverityBadge severity={alert.severity} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-slate-200">{alert.title}</div>
            <div className="text-xs text-slate-500">
              <span className="font-mono">{alert.source_ip ?? '—'}</span> ·{' '}
              {formatTimestamp(alert.created_at)}
            </div>
          </div>
        </li>
      ))}
    </ul>
  )
}
