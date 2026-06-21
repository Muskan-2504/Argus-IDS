import type { Severity } from '../api/types'

// Static class strings (so Tailwind doesn't purge them).
const STYLES: Record<Severity, string> = {
  critical: 'bg-red-500/15 text-red-400 ring-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 ring-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 ring-yellow-500/30',
  low: 'bg-green-500/15 text-green-400 ring-green-500/30',
  info: 'bg-sky-500/15 text-sky-400 ring-sky-500/30',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium uppercase ring-1 ring-inset ${STYLES[severity]}`}
    >
      {severity}
    </span>
  )
}
