import type { Alert } from '../api/types'

function Card({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${accent}`}>{value}</div>
    </div>
  )
}

export function StatCards({ alerts }: { alerts: Alert[] }) {
  const open = alerts.filter((a) => a.status === 'open').length
  const critical = alerts.filter((a) => a.severity === 'critical' || a.severity === 'high').length
  const sources = new Set(alerts.map((a) => a.source_ip).filter(Boolean)).size

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <Card label="Total alerts" value={alerts.length} accent="text-slate-100" />
      <Card label="Open" value={open} accent="text-red-400" />
      <Card label="High / critical" value={critical} accent="text-orange-400" />
      <Card label="Source IPs" value={sources} accent="text-sky-400" />
    </div>
  )
}
