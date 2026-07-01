import type { MitreCoverage as Coverage } from '../api/types'
import { mitreUrl } from '../lib/format'

// Group the covered techniques by ATT&CK tactic for a compact, scannable view.
function groupByTactic(coverage: Coverage[]): [string, Coverage[]][] {
  const groups = new Map<string, Coverage[]>()
  for (const item of coverage) {
    const tactic = item.tactic ?? 'Other'
    groups.set(tactic, [...(groups.get(tactic) ?? []), item])
  }
  return [...groups.entries()]
}

export function MitreCoverage({ coverage }: { coverage: Coverage[] }) {
  if (coverage.length === 0) {
    return <p className="text-sm text-slate-500">No techniques covered yet.</p>
  }

  return (
    <div className="flex flex-wrap gap-3">
      {groupByTactic(coverage).map(([tactic, techniques]) => (
        <div
          key={tactic}
          className="min-w-[180px] flex-1 rounded-lg border border-slate-800 bg-slate-900/60 p-3"
        >
          <div className="text-xs font-semibold uppercase tracking-wide text-sky-400">{tactic}</div>
          <ul className="mt-2 space-y-1.5">
            {techniques.map((t) => (
              <li key={t.technique} className="flex items-center justify-between gap-2">
                <a
                  href={mitreUrl(t.technique)}
                  target="_blank"
                  rel="noreferrer"
                  className="text-sm text-slate-300 hover:underline"
                  title={t.technique}
                >
                  {t.name ?? t.technique}
                </a>
                <span
                  title={`${t.alert_count} alert(s) raised`}
                  className="shrink-0 rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400"
                >
                  {t.alert_count}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  )
}
