import { useCallback, useEffect, useRef, useState } from 'react'

import { ApiError, api } from '../api/client'
import type { Alert, AlertFilters as Filters, AlertStatus } from '../api/types'
import { useAlertStream } from '../api/useAlertStream'
import { useAuth } from '../auth/useAuth'
import { AlertFilters } from '../components/AlertFilters'
import { AlertTable } from '../components/AlertTable'
import { Header } from '../components/Header'
import { LiveFeed } from '../components/LiveFeed'
import { SeverityChart } from '../components/SeverityChart'
import { StatCards } from '../components/StatCards'
import { TimelineChart } from '../components/TimelineChart'
import { WorldMap } from '../components/WorldMap'

// Fallback poll if the WebSocket drops.
const POLL_MS = 15_000

const PANEL = 'rounded-xl border border-slate-800 bg-slate-900/40 p-4'

function prepend(list: Alert[], alert: Alert, cap: number): Alert[] {
  return [alert, ...list.filter((a) => a.id !== alert.id)].slice(0, cap)
}

export function Dashboard() {
  const { user } = useAuth()
  const canTriage = user?.role === 'admin' || user?.role === 'analyst'

  const [alerts, setAlerts] = useState<Alert[]>([])
  const [liveFeed, setLiveFeed] = useState<Alert[]>([])
  const [filters, setFilters] = useState<Filters>({})
  const [error, setError] = useState<string | null>(null)

  const hasFilters = Boolean(filters.severity || filters.status || filters.source_ip)
  const hasFiltersRef = useRef(hasFilters)
  hasFiltersRef.current = hasFilters

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

  // Live stream: always feed the ticker; merge into the table when unfiltered.
  const onStreamAlert = useCallback((alert: Alert) => {
    setLiveFeed((prev) => prepend(prev, alert, 15))
    if (!hasFiltersRef.current) setAlerts((prev) => prepend(prev, alert, 200))
  }, [])
  const connected = useAlertStream(onStreamAlert)

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
          {connected ? (
            <span className="flex items-center gap-2 text-xs text-green-400">
              <span className="h-2 w-2 animate-pulse rounded-full bg-green-500" />
              Live
            </span>
          ) : (
            <span className="flex items-center gap-2 text-xs text-amber-400">
              <span className="h-2 w-2 rounded-full bg-amber-500" />
              Polling every {POLL_MS / 1000}s
            </span>
          )}
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

        <div className="grid gap-6 lg:grid-cols-3">
          <section className={`${PANEL} lg:col-span-2`}>
            <h2 className="mb-3 text-sm font-semibold text-slate-300">Attack origins</h2>
            <WorldMap alerts={alerts} />
          </section>
          <section className={PANEL}>
            <h2 className="mb-3 text-sm font-semibold text-slate-300">Live feed</h2>
            <LiveFeed alerts={liveFeed} />
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
