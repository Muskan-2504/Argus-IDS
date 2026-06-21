import { useState } from 'react'
import type { FormEvent } from 'react'

import { ApiError } from '../api/client'
import { useAuth } from '../auth/useAuth'

export function LoginForm() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      await login(username, password)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Login failed. Please try again.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm space-y-5 rounded-2xl border border-slate-800 bg-slate-900/60 p-8 shadow-xl"
      >
        <div className="flex flex-col items-center gap-2 text-center">
          <img src="/argus.svg" alt="Argus" className="h-12 w-12" />
          <h1 className="text-xl font-semibold tracking-tight">Argus</h1>
          <p className="text-sm text-slate-400">Intrusion Detection System</p>
        </div>

        <label className="block text-sm">
          <span className="mb-1 block text-slate-300">Username</span>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-sky-500"
          />
        </label>

        <label className="block text-sm">
          <span className="mb-1 block text-slate-300">Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-sky-500"
          />
        </label>

        {error && (
          <p className="rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</p>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded-lg bg-sky-600 px-3 py-2 font-medium text-white transition hover:bg-sky-500 disabled:opacity-50"
        >
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
