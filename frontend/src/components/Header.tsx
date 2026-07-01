import { NavLink } from 'react-router-dom'

import { useAuth } from '../auth/useAuth'

type NavItem = { to: string; label: string; end?: boolean; analystOnly?: boolean }

const NAV: NavItem[] = [
  { to: '/', label: 'Home', end: true },
  { to: '/analyze', label: 'Analyze Logs', analystOnly: true },
  { to: '/dashboard', label: 'Dashboard' },
]

const linkClass = (isActive: boolean): string =>
  isActive
    ? 'rounded-md bg-slate-800 px-3 py-1 font-medium text-slate-100'
    : 'rounded-md px-3 py-1 text-slate-400 transition hover:bg-slate-800/60 hover:text-slate-200'

export function Header() {
  const { user, logout } = useAuth()
  const canAnalyze = user?.role === 'admin' || user?.role === 'analyst'
  const items = NAV.filter((item) => !item.analystOnly || canAnalyze)

  return (
    <header className="border-b border-slate-800 bg-slate-900/60">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3">
        <div className="flex items-center gap-6">
          <NavLink to="/" className="flex items-center gap-2">
            <img src="/argus.svg" className="h-7 w-7" alt="" />
            <span className="font-semibold tracking-tight">Argus</span>
            <span className="hidden text-xs text-slate-500 sm:inline">Intrusion Detection</span>
          </NavLink>
          <nav className="flex items-center gap-1 text-sm">
            {items.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.end}>
                {({ isActive }) => <span className={linkClass(isActive)}>{item.label}</span>}
              </NavLink>
            ))}
          </nav>
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
