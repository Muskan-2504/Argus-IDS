import { ALERT_STATUSES, type Alert, type AlertStatus } from '../api/types'
import { formatTimestamp, mitreUrl } from '../lib/format'
import { STATUS_LABELS } from '../lib/labels'
import { SeverityBadge } from './SeverityBadge'
import { StatusBadge } from './StatusBadge'

interface Props {
  alerts: Alert[]
  canTriage: boolean
  onTriage: (id: number, status: AlertStatus) => void
}

export function AlertTable({ alerts, canTriage, onTriage }: Props) {
  if (alerts.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-10 text-center text-slate-500">
        No alerts match the current filters.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800">
      <table className="min-w-full divide-y divide-slate-800 text-sm">
        <thead className="bg-slate-900/60 text-left text-xs uppercase tracking-wide text-slate-400">
          <tr>
            <th className="px-4 py-3">Severity</th>
            <th className="px-4 py-3">Alert</th>
            <th className="px-4 py-3">Source IP</th>
            <th className="px-4 py-3">MITRE</th>
            <th className="px-4 py-3">Detected</th>
            <th className="px-4 py-3">Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/70">
          {alerts.map((alert) => (
            <tr key={alert.id} className="hover:bg-slate-900/40">
              <td className="px-4 py-3">
                <SeverityBadge severity={alert.severity} />
              </td>
              <td className="px-4 py-3">
                <div className="font-medium text-slate-100">{alert.title}</div>
                {alert.description && (
                  <div className="text-xs text-slate-500">{alert.description}</div>
                )}
              </td>
              <td className="px-4 py-3 font-mono text-slate-300">{alert.source_ip ?? '—'}</td>
              <td className="px-4 py-3">
                {alert.mitre_technique ? (
                  <a
                    href={mitreUrl(alert.mitre_technique)}
                    target="_blank"
                    rel="noreferrer"
                    className="text-sky-400 hover:underline"
                  >
                    {alert.mitre_technique}
                  </a>
                ) : (
                  '—'
                )}
              </td>
              <td className="whitespace-nowrap px-4 py-3 text-slate-400">
                {formatTimestamp(alert.created_at)}
              </td>
              <td className="px-4 py-3">
                {canTriage ? (
                  <select
                    value={alert.status}
                    onChange={(e) => onTriage(alert.id, e.target.value as AlertStatus)}
                    className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-xs outline-none focus:border-sky-500"
                  >
                    {ALERT_STATUSES.map((status) => (
                      <option key={status} value={status}>
                        {STATUS_LABELS[status]}
                      </option>
                    ))}
                  </select>
                ) : (
                  <StatusBadge status={alert.status} />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
