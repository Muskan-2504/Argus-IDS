import { useCallback, useEffect, useState } from 'react'

import { ApiError, api } from '../api/client'
import type { Alert, AlertFilters as Filters, AlertStatus } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { AlertFilters } from '../components/AlertFilters'
import { AlertTable } from '../components/AlertTable'
import { Header } from '../components/Header'
import { SeverityChart } from '../components/SeverityChart'
import { StatCards } from '../components/StatCards'
import { TimelineChart } from '../components/TimelineChart'

// Poll for fresh alerts. Replaced by a WebSocket push in M4.
const POLL_MS = 10_000

const PANEL = 'rounded-xl border border-slate-800 bg-slate-900/40 p-4'

export function Dashboard() {
  const { user } = useAuth()
  const canTriage = user?.role === 'admin' || user?.role === 'analyst'

  const [alerts, setAlerts] = useState<Alert[]>([])
  const [filters, setFilters] = useState<Filters>({})
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setAlerts(await api.listAlerts({ ...filters, limit: 200 }))
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load alerts.')
    }
  }, [filters])

  useEffect(() => {
    void load()
    const timer = setInterval(() => void load(), POLL_MS)
    return () => clearInterval(timer)
  }, [load])

  const handleTriage = useCallback(
    async (id: number, status: AlertStatus) => {
      await api.updateAlertStatus(id, status)
      void load()
    },
    [load],
  )

  return (
    <div className="min-h-screen">
      <Header />
      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6">
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-semibold">Threat Overview</h1>
          <span className="flex items-center gap-2 text-xs text-slate-500">
            <span className="h-2 w-2 animate-pulse rounded-full bg-green-500" />
            Live · refreshes every {POLL_MS / 1000}s
          </span>
        </div>

        <StatCards alerts={alerts} />

        <div className="grid gap-6 lg:grid-cols-3">
          <section className={PANEL}>
            <h2 className="mb-3 text-sm font-semibold text-slate-300">Alerts by severity</h2>
            <SeverityChart alerts={alerts} />
          </section>
          <section className={`${PANEL} lg:col-span-2`}>
            <h2 className="mb-3 text-sm font-semibold text-slate-300">Alert volume over time</h2>
            <TimelineChart alerts={alerts} />
          </section>
        </div>

        <section className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-sm font-semibold text-slate-300">Alerts</h2>
            <AlertFilters filters={filters} onChange={setFilters} />
          </div>
          {error && (
            <p className="rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</p>
          )}
          <AlertTable alerts={alerts} canTriage={canTriage} onTriage={handleTriage} />
        </section>
      </main>
    </div>
  )
}
