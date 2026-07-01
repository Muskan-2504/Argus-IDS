import { Link } from 'react-router-dom'

import { useAuth } from '../auth/useAuth'

const PANEL = 'rounded-xl border border-slate-800 bg-slate-900/40 p-5'

export function Home() {
  const { user } = useAuth()
  const canAnalyze = user?.role === 'admin' || user?.role === 'analyst'

  return (
    <main className="mx-auto max-w-7xl space-y-12 px-4 py-10">
      {/* Hero */}
      <section className="flex flex-col items-center gap-5 py-10 text-center">
        <img src="/argus.svg" className="h-16 w-16" alt="" />
        <p className="text-sm uppercase tracking-widest text-sky-400">Intrusion Detection System</p>
        <h1 className="max-w-3xl text-4xl font-bold tracking-tight text-slate-100 sm:text-5xl">
          See every intrusion hiding in your logs
        </h1>
        <p className="max-w-2xl text-lg text-slate-400">
          Argus reads your server logs, finds attacks — brute force, SQL injection, port scans,
          behavioral anomalies — and lays them out on a live, MITRE-mapped dashboard. Paste a log
          and find out in seconds.
        </p>
        <div className="mt-2 flex flex-wrap items-center justify-center gap-3">
          {canAnalyze && (
            <Link
              to="/analyze"
              className="rounded-lg bg-sky-600 px-6 py-3 text-base font-semibold text-white shadow-lg shadow-sky-900/30 transition hover:bg-sky-500"
            >
              Analyze your logs →
            </Link>
          )}
          <Link
            to="/dashboard"
            className="rounded-lg border border-slate-700 px-6 py-3 text-base font-medium text-slate-200 transition hover:bg-slate-800"
          >
            View the dashboard
          </Link>
        </div>
        <p className="text-xs text-slate-500">
          Signed in as <span className="text-slate-300">{user?.username}</span> · self-hosted &amp;
          private — your logs never leave this machine
        </p>
      </section>

      {/* What you can do */}
      <section className="space-y-4">
        <h2 className="text-center text-sm font-semibold uppercase tracking-widest text-slate-500">
          What you can do
        </h2>
        <div className="grid gap-5 md:grid-cols-3">
          {/* Primary / highlighted feature */}
          <Link
            to={canAnalyze ? '/analyze' : '/dashboard'}
            className="group rounded-xl border border-sky-700/60 bg-sky-950/30 p-5 ring-1 ring-sky-500/10 transition hover:border-sky-500 hover:bg-sky-950/50 md:row-span-1"
          >
            <div className="mb-2 flex items-center gap-2">
              <span className="rounded-md bg-sky-500/20 px-2 py-0.5 text-xs font-semibold text-sky-300">
                Start here
              </span>
            </div>
            <h3 className="text-lg font-semibold text-slate-100">Analyze Logs</h3>
            <p className="mt-1 text-sm text-slate-400">
              Paste any log — SSH, web access, firewall, JSON, or something custom. Argus
              auto-detects the format, extracts the key fields (IPs, ports, paths, outcomes), and
              scans for threats instantly. No setup, no format wrangling.
            </p>
            <span className="mt-3 inline-block text-sm font-medium text-sky-400 group-hover:text-sky-300">
              {canAnalyze ? 'Analyze logs →' : 'View results →'}
            </span>
          </Link>

          <div className={PANEL}>
            <h3 className="text-lg font-semibold text-slate-100">Live Dashboard</h3>
            <p className="mt-1 text-sm text-slate-400">
              Your triage center: severity breakdown, an attack-origin world map, an alert timeline,
              a live feed, and one-click status updates for every threat.
            </p>
            <Link
              to="/dashboard"
              className="mt-3 inline-block text-sm font-medium text-sky-400 hover:text-sky-300"
            >
              Open dashboard →
            </Link>
          </div>

          <div className={PANEL}>
            <h3 className="text-lg font-semibold text-slate-100">Detection Engine</h3>
            <p className="mt-1 text-sm text-slate-400">
              Sigma-style signature rules plus statistical and machine-learning anomaly detection —
              each finding mapped to MITRE ATT&amp;CK and risk-scored 0–100.
            </p>
            <span className="mt-3 inline-block text-xs text-slate-500">
              Brute force · DoS · port scan · SQLi · anomalies
            </span>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="space-y-4">
        <h2 className="text-center text-sm font-semibold uppercase tracking-widest text-slate-500">
          How it works
        </h2>
        <div className="grid gap-5 md:grid-cols-3">
          {[
            {
              n: '1',
              t: 'Paste your logs',
              d: 'Drop in log lines (or load a built-in sample). Leave the format on auto-detect.',
            },
            {
              n: '2',
              t: 'Argus detects threats',
              d: 'Rules and anomaly models scan the batch and raise scored, MITRE-tagged alerts.',
            },
            {
              n: '3',
              t: 'Triage on the dashboard',
              d: 'Review, filter, and update alert status as you work through what was found.',
            },
          ].map((step) => (
            <div key={step.n} className={PANEL}>
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-800 text-sm font-semibold text-sky-400">
                {step.n}
              </div>
              <h3 className="mt-3 font-semibold text-slate-100">{step.t}</h3>
              <p className="mt-1 text-sm text-slate-400">{step.d}</p>
            </div>
          ))}
        </div>
      </section>
    </main>
  )
}
