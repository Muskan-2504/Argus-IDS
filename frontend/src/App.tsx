import { AuthProvider } from './auth/AuthProvider'
import { useAuth } from './auth/useAuth'
import { LoginForm } from './components/LoginForm'

function AppShell() {
  const { user, loading, logout } = useAuth()

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center text-slate-400">Loading…</div>
    )
  }

  if (!user) return <LoginForm />

  // Replaced by the full dashboard in a later M3 commit.
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4">
      <p className="text-slate-300">
        Signed in as <span className="font-semibold">{user.username}</span> ({user.role})
      </p>
      <button onClick={logout} className="rounded-lg bg-slate-800 px-4 py-2 hover:bg-slate-700">
        Sign out
      </button>
    </div>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <AppShell />
    </AuthProvider>
  )
}
