import { useAuth } from '../auth/useAuth'

export function Header() {
  const { user, logout } = useAuth()
  return (
    <header className="border-b border-slate-800 bg-slate-900/60">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3">
        <div className="flex items-center gap-2">
          <img src="/argus.svg" className="h-7 w-7" alt="" />
          <span className="font-semibold tracking-tight">Argus</span>
          <span className="hidden text-xs text-slate-500 sm:inline">Intrusion Detection</span>
        </div>
        <div className="flex items-center gap-3 text-sm">
          <span className="text-slate-400">
            {user?.username} · <span className="text-slate-500">{user?.role}</span>
          </span>
          <button
            onClick={logout}
            className="rounded-md border border-slate-700 px-3 py-1 transition hover:bg-slate-800"
          >
            Sign out
          </button>
        </div>
      </div>
    </header>
  )
}
