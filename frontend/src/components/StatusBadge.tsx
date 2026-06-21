import type { AlertStatus } from '../api/types'
import { STATUS_LABELS } from '../lib/labels'

const STYLES: Record<AlertStatus, string> = {
  open: 'bg-red-500/15 text-red-400',
  acknowledged: 'bg-yellow-500/15 text-yellow-400',
  resolved: 'bg-green-500/15 text-green-400',
  false_positive: 'bg-slate-500/20 text-slate-400',
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${STYLES[status]}`}>
      {STATUS_LABELS[status]}
    </span>
  )
}
