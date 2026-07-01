import { useAnalyze } from '../analyze/useAnalyze'
import { ApiError, api } from '../api/client'
import type { AnalyzeResult } from '../api/types'
import { SeverityBadge } from '../components/SeverityBadge'
import { ANALYZABLE_FORMATS, SOURCE_TYPE_LABELS } from '../lib/labels'
import { SAMPLE_LOGS } from '../lib/sampleLogs'

const PANEL = 'rounded-xl border border-slate-800 bg-slate-900/40 p-4'

export function AnalyzePage() {
  // State lives in the AnalyzeProvider so it survives navigating to the
  // dashboard and back; it only resets on a full page refresh.
  const { text, setText, format, setFormat, result, setResult, error, setError, loading, setLoading, clear } =
    useAnalyze()

  const scan = async () => {
    setLoading(true)
    setError(null)
    try {
      setResult(
        await api.analyzeLogs({
          text,
          source_type: format === 'auto' ? null : format,
        }),
      )
    } catch (err) {
      setResult(null)
      setError(err instanceof ApiError ? err.message : 'Could not analyze the logs.')
    } finally {
      setLoading(false)
    }
  }

  const loadSample = (sampleText: string) => {
    setText(sampleText)
    setFormat('auto')
    setResult(null)
    setError(null)
  }

  return (
    <main className="mx-auto max-w-7xl space-y-6 px-4 py-6">
      <div>
        <h1 className="text-lg font-semibold">Analyze Logs</h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-400">
          Paste log lines from your server and Argus scans them for intrusion attempts — SSH
          brute-force, SQL injection, port scans, and more. Works with any format: leave it on
          auto-detect and Argus extracts the key fields (IPs, ports, paths, outcomes) even from logs
          it has never seen.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className={`${PANEL} space-y-4`}>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm">
              <span className="mb-1 block text-slate-400">Log format</span>
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value as typeof format)}
                className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm"
              >
                <option value="auto">Auto-detect</option>
                {ANALYZABLE_FORMATS.map((f) => (
                  <option key={f.value} value={f.value}>
                    {f.label}
                  </option>
                ))}
              </select>
            </label>
            <div className="text-xs text-slate-500">
              <span className="mb-1 block text-slate-400">Load a sample</span>
              <div className="flex flex-wrap gap-2">
                {SAMPLE_LOGS.map((s) => (
                  <button
                    key={s.id}
                    title={s.blurb}
                    onClick={() => loadSample(s.text)}
                    className="rounded-md border border-slate-700 px-2.5 py-1.5 text-slate-300 transition hover:bg-slate-800"
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            spellCheck={false}
            rows={16}
            placeholder={
              'Paste raw log lines here, one per line — e.g.\n' +
              'Jun 10 06:11:01 web-01 sshd[20144]: Failed password for root from 203.0.113.5 port 54001 ssh2'
            }
            className="w-full resize-y rounded-md border border-slate-700 bg-slate-950/60 p-3 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-slate-500 focus:outline-none"
          />

          <div className="flex items-center gap-3">
            <button
              onClick={scan}
              disabled={loading || text.trim() === ''}
              className="rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {loading ? 'Scanning…' : 'Scan for threats'}
            </button>
            {text !== '' && (
              <button
                onClick={clear}
                className="text-sm text-slate-400 transition hover:text-slate-200"
              >
                Clear
              </button>
            )}
          </div>

          <p className="border-t border-slate-800 pt-3 text-xs text-slate-500">
            🔒 Runs locally. Logs you paste are analyzed on your own machine and stored in your own
            database — nothing is sent to a third party.
          </p>
        </section>

        <section className={PANEL}>
          <h2 className="mb-3 text-sm font-semibold text-slate-300">Results</h2>
          <Results loading={loading} error={error} result={result} />
        </section>
      </div>
    </main>
  )
}

function Results({
  loading,
  error,
  result,
}: {
  loading: boolean
  error: string | null
  result: AnalyzeResult | null
}) {
  if (loading) {
    return <p className="text-sm text-slate-400">Scanning your logs…</p>
  }
  if (error) {
    return <p className="rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</p>
  }
  if (!result) {
    return (
      <p className="text-sm text-slate-500">
        Paste logs (or load a sample) and hit{' '}
        <span className="text-slate-300">Scan for threats</span> to see what Argus finds.
      </p>
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
        <span className="rounded-full bg-slate-800 px-2 py-0.5 text-slate-300">
          {result.auto_detected ? 'Detected: ' : ''}
          {SOURCE_TYPE_LABELS[result.detected_source_type]}
        </span>
        <span>
          {result.parsed} of {result.received} lines parsed
        </span>
        {result.skipped > 0 && <span className="text-amber-400">{result.skipped} skipped</span>}
      </div>

      {result.parsed === 0 ? (
        <p className="rounded-lg bg-amber-500/10 px-3 py-2 text-sm text-amber-300">
          Nothing parsed. These lines don&apos;t match the{' '}
          {SOURCE_TYPE_LABELS[result.detected_source_type]} format — try a different format above, or
          check that you pasted complete log lines.
        </p>
      ) : result.alerts.length === 0 ? (
        <p className="rounded-lg bg-green-500/10 px-3 py-2 text-sm text-green-300">
          ✓ No new threats detected in these logs. (An attacker already flagged on your dashboard
          won&apos;t be re-raised until you resolve it.)
        </p>
      ) : (
        <>
          <p className="text-sm text-slate-300">
            {result.alerts.length} threat{result.alerts.length > 1 ? 's' : ''} found — now on your
            dashboard.
          </p>
          <ul className="space-y-2">
            {result.alerts.map((a) => (
              <li key={a.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                <div className="flex items-start justify-between gap-2">
                  <span className="font-medium text-slate-200">{a.title}</span>
                  <SeverityBadge severity={a.severity} />
                </div>
                {a.description && <p className="mt-1 text-xs text-slate-400">{a.description}</p>}
                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
                  {a.source_ip && (
                    <span>
                      Source <span className="text-slate-300">{a.source_ip}</span>
                    </span>
                  )}
                  {a.mitre_technique && (
                    <span>
                      MITRE <span className="text-slate-300">{a.mitre_technique}</span>
                      {a.technique_name && (
                        <span className="text-slate-400"> · {a.technique_name}</span>
                      )}
                    </span>
                  )}
                  <span>
                    Risk <span className="text-slate-300">{a.score}</span>
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}
