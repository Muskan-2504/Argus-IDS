import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'

import { AnalyzeProvider } from './analyze/AnalyzeProvider'
import { AuthProvider } from './auth/AuthProvider'
import { useAuth } from './auth/useAuth'
import { Header } from './components/Header'
import { LoginForm } from './components/LoginForm'
import { AnalyzePage } from './pages/AnalyzePage'
import { Dashboard } from './pages/Dashboard'
import { Home } from './pages/Home'

function AppShell() {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center text-slate-400">Loading…</div>
    )
  }

  if (!user) return <LoginForm />

  return (
    <AnalyzeProvider>
      <div className="min-h-screen">
        <Header />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/analyze" element={<AnalyzePage />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </AnalyzeProvider>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <AppShell />
      </BrowserRouter>
    </AuthProvider>
  )
}
