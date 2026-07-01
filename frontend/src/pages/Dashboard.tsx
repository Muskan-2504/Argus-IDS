import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'

import { ApiError, api } from '../api/client'
import type {
  Alert,
  AlertFilters as Filters,
  AlertStatus,
  MitreCoverage as Coverage,
} from '../api/types'
import { useAlertStream } from '../api/useAlertStream'
import { useAuth } from '../auth/useAuth'
import { AlertFilters } from '../components/AlertFilters'
import { AlertTable } from '../components/AlertTable'
import { LiveFeed } from '../components/LiveFeed'
import { MitreCoverage } from '../components/MitreCoverage'
import { SeverityChart } from '../components/SeverityChart'
import { StatCards } from '../components/StatCards'
import { TimelineChart } from '../components/TimelineChart'
import { WorldMap } from '../components/WorldMap'
import { SAMPLE_LOGS } from '../lib/sampleLogs'

// Fallback poll if the WebSocket drops.
const POLL_MS = 15_000

const PANEL = 'rounded-xl border border-slate-800 bg-slate-900/40 p-4'

function prepend(list: Alert[], alert: Alert, cap: number): Alert[] {
  return [alert, ...list.filter((a) => a.id !== alert.id)].slice(0, cap)
}

export function Dashboard() {
  const { user } = useAuth()
  const canTriage = user?.role === 'admin' || user?.role === 'analyst'
  const isAdmin = user?.role === 'admin'

  const [alerts, setAlerts] = useState<Alert[]>([])
  const [liveFeed, setLiveFeed] = useState<Alert[]>([])
  const [coverage, setCoverage] = useState<Coverage[]>([])
  const [filters, setFilters] = useState<Filters>({})
  const [error, setError] = useState<string | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState<'sample' | 'clear' | null>(null)

  const hasFilters = Boolean(filters.severity || filters.status || filters.source_ip)
  const hasFiltersRef = useRef(hasFilters)
  hasFiltersRef.current = hasFilters

  const load = useCallback(async () => {
    try {
      const [list, cov] = await Promise.all([
        api.listAlerts({ ...filters, limit: 200 }),
        canTriage ? api.mitreCoverage() : Promise.resolve<Coverage[]>([]),
      ])
      setAlerts(list)
      setCoverage(cov)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load alerts.')
    } finally {
      setLoaded(true)
    }
  }, [filters, canTriage])

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

  const loadSample = useCallback(async () => {
    setBusy('sample')
    setError(null)
    try {
      for (const sample of SAMPLE_LOGS) {
        await api.analyzeLogs({ text: sample.text, source_type: null })
      }
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load sample data.')
    } finally {
      setBusy(null)
    }
  }, [load])

  const clearAll = useCallback(async () => {
    if (!window.confirm('Delete all events and alerts? This cannot be undone.')) return
    setBusy('clear')
    setError(null)
    try {
      await api.clearData()
      setLiveFeed([])
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to clear data.')
    } finally {
      setBusy(null)
    }
  }, [load])

  const isEmpty = loaded && alerts.length === 0 && !hasFilters

  return (
    <main className="mx-auto max-w-7xl space-y-6 px-4 py-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <h1 className="text-lg font-semibold">Threat Overview</h1>
          {!isEmpty && alerts.length > 0 && (
            <span
              title="Demo data from analyzed logs. Use Clear all to reset, then analyze your own."
              className="rounded-full border border-slate-700 px-2 py-0.5 text-[11px] text-slate-400"
            >
              Sample data
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {canTriage && (
            <button
              onClick={loadSample}
              disabled={busy !== null}
              className="rounded-md border border-slate-700 px-3 py-1 text-xs text-slate-300 transition hover:bg-slate-800 disabled:opacity-40"
            >
              {busy === 'sample' ? 'Loading…' : 'Load sample data'}
            </button>
          )}
          {isAdmin && (
            <button
              onClick={clearAll}
              disabled={busy !== null}
              className="rounded-md border border-red-900/60 px-3 py-1 text-xs text-red-400 transition hover:bg-red-950/40 disabled:opacity-40"
            >
              {busy === 'clear' ? 'Clearing…' : 'Clear all'}
            </button>
          )}
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
      </div>

      {error && <p className="rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</p>}

      {isEmpty ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-12 text-center">
          <img src="/argus.svg" className="mx-auto h-12 w-12 opacity-60" alt="" />
          <h2 className="mt-4 text-lg font-semibold text-slate-200">No threats yet</h2>
          <p className="mx-auto mt-1 max-w-md text-sm text-slate-400">
            Analyze some logs and any attacks Argus finds will appear here — severity breakdown,
            attack origins, timeline, and triage.
          </p>
          {canTriage && (
            <div className="mt-5 flex flex-wrap items-center justify-center gap-3">
              <Link
                to="/analyze"
                className="rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-sky-500"
              >
                Analyze logs →
              </Link>
              <button
                onClick={loadSample}
                disabled={busy !== null}
                className="rounded-md border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:bg-slate-800 disabled:opacity-40"
              >
                {busy === 'sample' ? 'Loading…' : 'Load sample data'}
              </button>
            </div>
          )}
        </div>
      ) : (
        <>
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

          {canTriage && coverage.length > 0 && (
            <section className={PANEL}>
              <h2 className="mb-3 text-sm font-semibold text-slate-300">MITRE ATT&CK coverage</h2>
              <MitreCoverage coverage={coverage} />
            </section>
          )}

          <section className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-sm font-semibold text-slate-300">Alerts</h2>
              <AlertFilters filters={filters} onChange={setFilters} />
            </div>
            <AlertTable alerts={alerts} canTriage={canTriage} onTriage={handleTriage} />
          </section>
        </>
      )}
    </main>
  )
}
